#![allow(dead_code)]

use crate::models::characters::Character;
use crate::models::lorebooks::Lorebook; // Import the new Lorebook
use chrono::{DateTime, Utc}; // Add DateTime and Utc
use diesel::prelude::*;
use diesel_json::Json;
use serde::{Deserialize, Serialize}; // Added Deserializer
use serde_json::Value; // Using Value for flexibility in extensions and mixed types like id
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use uuid::Uuid; // <-- Add Uuid import // Alias serde_json::Value // Add use statement for canonical Character struct

// Main Character Card Structure (V3)
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CharacterCardV3 {
    #[serde(default)] // Use default for spec fields if missing in JSON
    pub spec: String,
    #[serde(default)]
    pub spec_version: String,
    #[serde(default)] // Uses Default impl of CharacterCardDataV3
    pub data: CharacterCardDataV3,
}

impl std::fmt::Debug for CharacterCardV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CharacterCardV3")
            .field("spec", &"[REDACTED]")
            .field("spec_version", &"[REDACTED]")
            .field("data", &self.data) // Relies on CharacterCardDataV3's Debug
            .finish()
    }
}

// Character Card Data Payload (V3)
#[derive(Serialize, Deserialize, Clone, Default)] // Add Default back
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

impl std::fmt::Debug for CharacterCardDataV3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CharacterCardDataV3")
            .field("name", &"[REDACTED]")
            .field("description", &"[REDACTED]")
            .field("personality", &"[REDACTED]")
            .field("scenario", &"[REDACTED]")
            .field("first_mes", &"[REDACTED]")
            .field("mes_example", &"[REDACTED]")
            .field("creator_notes", &"[REDACTED]")
            .field("system_prompt", &"[REDACTED]")
            .field("post_history_instructions", &"[REDACTED]")
            .field("alternate_greetings", &"[REDACTED]")
            .field("tags", &"[REDACTED]")
            .field("creator", &"[REDACTED]")
            .field("character_version", &"[REDACTED]")
            .field("extensions", &"[REDACTED]")
            .field("character_book", &self.character_book) // Relies on Lorebook's Debug
            .field("assets", &self.assets) // Relies on Asset's Debug
            .field("nickname", &"[REDACTED]")
            .field("creator_notes_multilingual", &"[REDACTED]")
            .field("source", &"[REDACTED]")
            .field("group_only_greetings", &"[REDACTED]")
            .field("creation_date", &self.creation_date)
            .field("modification_date", &self.modification_date)
            .finish()
    }
}

// Asset Definition (within assets array)
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Asset {
    pub r#type: String, // Using r# prefix as 'type' is a Rust keyword
    pub uri: String,
    pub name: String,
    pub ext: String,
}

impl std::fmt::Debug for Asset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Asset")
            .field("r#type", &"[REDACTED]")
            .field("uri", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .field("ext", &"[REDACTED]")
            .finish()
    }
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

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Decorator {
    pub name: String,
    pub value: Option<String>,     // Store raw value string for flexibility
    pub fallbacks: Vec<Decorator>, // For @@@ fallback mechanism
}

impl std::fmt::Debug for Decorator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decorator")
            .field("name", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .field("fallbacks", &self.fallbacks) // Relies on recursive Debug for Decorator
            .finish()
    }
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
#[derive(Serialize, Deserialize, Clone)] // Removed Debug
pub struct StandaloneLorebook {
    pub spec: String, // Should be "lorebook_v3"
    pub data: Lorebook,
}

impl std::fmt::Debug for StandaloneLorebook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandaloneLorebook")
            .field("spec", &"[REDACTED]")
            .field("data", &self.data) // Relies on Lorebook's Debug
            .finish()
    }
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

use crate::schema::character_assets;
// use crate::models::users::User; // Unused import

// Note: For Insertable, we might need a separate struct `NewCharacter`
// if some fields (like id, created_at, updated_at) are not set manually during insertion.
#[derive(Insertable, Default, Clone)] // Added Default and Clone, Removed Debug
#[diesel(table_name = crate::schema::characters)]
pub struct NewCharacter {
    pub user_id: Uuid,
    pub spec: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<Vec<u8>>,
    pub description_nonce: Option<Vec<u8>>,
    pub personality: Option<Vec<u8>>,
    pub personality_nonce: Option<Vec<u8>>,
    pub scenario: Option<Vec<u8>>,
    pub scenario_nonce: Option<Vec<u8>>,
    pub first_mes: Option<Vec<u8>>,
    pub first_mes_nonce: Option<Vec<u8>>,
    pub mes_example: Option<Vec<u8>>,
    pub mes_example_nonce: Option<Vec<u8>>,
    pub creator_notes: Option<Vec<u8>>,
    pub creator_notes_nonce: Option<Vec<u8>>,
    pub system_prompt: Option<Vec<u8>>,
    pub system_prompt_nonce: Option<Vec<u8>>,
    pub post_history_instructions: Option<Vec<u8>>,
    pub post_history_instructions_nonce: Option<Vec<u8>>,
    pub tags: Option<Vec<Option<String>>>,
    pub creator: Option<String>,
    pub character_version: Option<String>,
    pub alternate_greetings: Option<Vec<Option<String>>>,
    pub nickname: Option<String>,
    pub creator_notes_multilingual: Option<Json<JsonValue>>,
    pub source: Option<Vec<Option<String>>>,
    pub group_only_greetings: Option<Vec<Option<String>>>,
    pub creation_date: Option<DateTime<Utc>>,
    pub modification_date: Option<DateTime<Utc>>,
    pub extensions: Option<Json<JsonValue>>, // Added extensions field
    // Fields from Character struct that are also in NewCharacter based on schema.rs and common use
    pub persona: Option<Vec<u8>>,
    pub persona_nonce: Option<Vec<u8>>,
    pub world_scenario: Option<Vec<u8>>,
    pub world_scenario_nonce: Option<Vec<u8>>,
    pub avatar: Option<String>,
    pub chat: Option<String>, // This seems like a V1/V2 field, usually not in new cards directly
    pub greeting: Option<Vec<u8>>,
    pub greeting_nonce: Option<Vec<u8>>,
    pub definition: Option<Vec<u8>>,
    pub definition_nonce: Option<Vec<u8>>,
    pub default_voice: Option<String>,
    // data_id: Option<i32>, // Usually not set on new character creation this way
    pub category: Option<String>,
    pub definition_visibility: Option<String>,
    // depth: Option<i32>,
    pub example_dialogue: Option<Vec<u8>>,
    pub example_dialogue_nonce: Option<Vec<u8>>,
    pub favorite: Option<bool>,
    pub first_message_visibility: Option<String>,
    // height: Option<BigDecimal>,
    // last_activity: Option<DateTime<Utc>>,
    pub migrated_from: Option<String>,
    pub model_prompt: Option<Vec<u8>>,
    pub model_prompt_nonce: Option<Vec<u8>>,
    pub model_prompt_visibility: Option<String>,
    // model_temperature: Option<BigDecimal>,
    // num_interactions: Option<i64>,
    // permanence: Option<BigDecimal>,
    pub persona_visibility: Option<String>,
    // revision: Option<i32>,
    pub sharing_visibility: Option<String>,
    pub status: Option<String>,
    pub system_prompt_visibility: Option<String>,
    pub system_tags: Option<Vec<Option<String>>>,
    pub token_budget: Option<i32>,
    pub usage_hints: Option<Json<JsonValue>>,
    pub user_persona: Option<Vec<u8>>,
    pub user_persona_nonce: Option<Vec<u8>>,
    pub user_persona_visibility: Option<String>,
    pub visibility: Option<String>,
    // weight: Option<BigDecimal>,
    pub world_scenario_visibility: Option<String>,
    // created_at and updated_at are typically handled by DB or set directly in handler
    pub created_at: Option<DateTime<Utc>>, // Make consistent with schema and Character struct
    pub updated_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for NewCharacter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewCharacter")
            .field("user_id", &self.user_id)
            .field("spec", &"[REDACTED]")
            .field("spec_version", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .field("description", &"[REDACTED_BYTES]")
            .field("description_nonce", &"[REDACTED_BYTES]")
            .field("personality", &"[REDACTED_BYTES]")
            .field("personality_nonce", &"[REDACTED_BYTES]")
            .field("scenario", &"[REDACTED_BYTES]")
            .field("scenario_nonce", &"[REDACTED_BYTES]")
            .field("first_mes", &"[REDACTED_BYTES]")
            .field("first_mes_nonce", &"[REDACTED_BYTES]")
            .field("mes_example", &"[REDACTED_BYTES]")
            .field("mes_example_nonce", &"[REDACTED_BYTES]")
            .field("creator_notes", &"[REDACTED_BYTES]")
            .field("creator_notes_nonce", &"[REDACTED_BYTES]")
            .field("system_prompt", &"[REDACTED_BYTES]")
            .field("system_prompt_nonce", &"[REDACTED_BYTES]")
            .field("post_history_instructions", &"[REDACTED_BYTES]")
            .field("post_history_instructions_nonce", &"[REDACTED_BYTES]")
            .field("tags", &"[REDACTED]")
            .field("creator", &"[REDACTED]")
            .field("character_version", &"[REDACTED]")
            .field("alternate_greetings", &"[REDACTED]")
            .field("nickname", &"[REDACTED]")
            .field("creator_notes_multilingual", &"[REDACTED_JSON]")
            .field("source", &"[REDACTED]")
            .field("group_only_greetings", &"[REDACTED]")
            .field("creation_date", &self.creation_date)
            .field("modification_date", &self.modification_date)
            .field("extensions", &"[REDACTED_JSON]")
            .field("persona", &"[REDACTED_BYTES]")
            .field("persona_nonce", &"[REDACTED_BYTES]")
            .field("world_scenario", &"[REDACTED_BYTES]")
            .field("world_scenario_nonce", &"[REDACTED_BYTES]")
            .field("avatar", &"[REDACTED]")
            .field("chat", &"[REDACTED]")
            .field("greeting", &"[REDACTED_BYTES]")
            .field("greeting_nonce", &"[REDACTED_BYTES]")
            .field("definition", &"[REDACTED_BYTES]")
            .field("definition_nonce", &"[REDACTED_BYTES]")
            .field("default_voice", &"[REDACTED]")
            .field("category", &"[REDACTED]")
            .field("definition_visibility", &"[REDACTED]")
            .field("example_dialogue", &"[REDACTED_BYTES]")
            .field("example_dialogue_nonce", &"[REDACTED_BYTES]")
            .field("favorite", &self.favorite)
            .field("first_message_visibility", &"[REDACTED]")
            .field("migrated_from", &"[REDACTED]")
            .field("model_prompt", &"[REDACTED_BYTES]")
            .field("model_prompt_nonce", &"[REDACTED_BYTES]")
            .field("model_prompt_visibility", &"[REDACTED]")
            .field("persona_visibility", &"[REDACTED]")
            .field("sharing_visibility", &"[REDACTED]")
            .field("status", &"[REDACTED]")
            .field("system_prompt_visibility", &"[REDACTED]")
            .field("system_tags", &"[REDACTED]")
            .field("token_budget", &self.token_budget)
            .field("usage_hints", &"[REDACTED_JSON]")
            .field("user_persona", &"[REDACTED_BYTES]")
            .field("user_persona_nonce", &"[REDACTED_BYTES]")
            .field("user_persona_visibility", &"[REDACTED]")
            .field("visibility", &"[REDACTED]")
            .field("world_scenario_visibility", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

// --- Conversion from Parsed Card to NewCharacter ---
use crate::services::character_parser::ParsedCharacterCard;

impl NewCharacter {
    // Add user_id parameter
    pub fn from_parsed_card(parsed: &ParsedCharacterCard, user_id: Uuid) -> Self {
        match parsed {
            ParsedCharacterCard::V3(data) => {
                // --- Handling V3 Card ---
                // Extract spec and version
                let spec = data.spec.clone();
                let spec_version = data.spec_version.clone();
                let data = data.data.clone(); // Clone the inner data

                // Convert V3 Vec<String> to DB Option<Vec<Option<String>>>
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
                let source = if data.source.as_ref().map_or(true, |s| s.is_empty()) {
                    None
                } else {
                    data.source.map(|s| s.into_iter().map(Some).collect())
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

                // Convert timestamps
                let creation_date_ts = data
                    .creation_date
                    .and_then(|ts| DateTime::from_timestamp(ts, 0));
                let modification_date_ts = data
                    .modification_date
                    .and_then(|ts| DateTime::from_timestamp(ts, 0));

                // Convert HashMaps to JsonValue for JSONB fields
                let creator_notes_multilingual_json = data
                    .creator_notes_multilingual
                    .as_ref()
                    .and_then(|m| serde_json::to_value(m).ok()) // Convert HashMap to JsonValue
                    .filter(|v| !v.is_null())
                    .map(Json); // Wrap Option<Value> in Json for Option<Json<Value>> type

                let extensions_json = data
                    .extensions // data.extensions is HashMap<String, Value>
                    .into_iter()
                    .collect::<serde_json::Map<String, serde_json::Value>>();
                let extensions_option_json = if extensions_json.is_empty() {
                    None
                } else {
                    Some(Json(serde_json::Value::Object(extensions_json))) // Wrap Value in Json for Option<Json<Value>>
                };

                NewCharacter {
                    user_id,                                     // Use passed user_id
                    name: data.name.clone().unwrap_or_default(), // V3 name is Option<String>, DB needs String
                    // Wrap non-optional V3 strings in Some() for DB Option<String>, filter empty
                    description: Some(data.description.clone().into_bytes())
                        .filter(|v| !v.is_empty()),
                    description_nonce: None,
                    personality: Some(data.personality.clone().into_bytes())
                        .filter(|v| !v.is_empty()),
                    personality_nonce: None,
                    scenario: Some(data.scenario.clone().into_bytes()).filter(|v| !v.is_empty()),
                    scenario_nonce: None,
                    first_mes: Some(data.first_mes.clone().into_bytes()).filter(|v| !v.is_empty()),
                    first_mes_nonce: None,
                    mes_example: Some(data.mes_example.clone().into_bytes())
                        .filter(|v| !v.is_empty()),
                    mes_example_nonce: None,
                    creator_notes: Some(data.creator_notes.clone().into_bytes())
                        .filter(|v| !v.is_empty()),
                    creator_notes_nonce: None,
                    system_prompt: Some(data.system_prompt.clone().into_bytes())
                        .filter(|v| !v.is_empty()),
                    system_prompt_nonce: None,
                    post_history_instructions: Some(
                        data.post_history_instructions.clone().into_bytes(),
                    )
                    .filter(|v| !v.is_empty()),
                    post_history_instructions_nonce: None,
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
                    creator_notes_multilingual: creator_notes_multilingual_json, // Assign the wrapped value
                    source,                          // Already Option<Vec<Option<String>>>
                    group_only_greetings,            // Already Option<Vec<Option<String>>>
                    creation_date: creation_date_ts, // Already Option<DateTime<Utc>>
                    modification_date: modification_date_ts, // Already Option<DateTime<Utc>>
                    extensions: extensions_option_json, // Assign the calculated extensions
                    persona: None,
                    persona_nonce: None,
                    world_scenario: None,
                    world_scenario_nonce: None,
                    avatar: None,
                    chat: None,
                    greeting: None,
                    greeting_nonce: None,
                    definition: None,
                    definition_nonce: None,
                    default_voice: None,
                    category: None,
                    definition_visibility: None,
                    example_dialogue: None,
                    example_dialogue_nonce: None,
                    favorite: None,
                    first_message_visibility: None,
                    migrated_from: None,
                    model_prompt: None,
                    model_prompt_nonce: None,
                    model_prompt_visibility: None,
                    persona_visibility: None,
                    sharing_visibility: None,
                    status: None,
                    system_prompt_visibility: None,
                    system_tags: None,
                    token_budget: None,
                    usage_hints: None,
                    user_persona: None,
                    user_persona_nonce: None,
                    user_persona_visibility: None,
                    visibility: None,
                    world_scenario_visibility: None,
                    created_at: None,
                    updated_at: None,
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
                    description: Some(data_v2.description.clone().into_bytes())
                        .filter(|v| !v.is_empty()),
                    description_nonce: None,
                    personality: Some(data_v2.personality.clone().into_bytes())
                        .filter(|v| !v.is_empty()),
                    personality_nonce: None,
                    scenario: Some(data_v2.scenario.clone().into_bytes()).filter(|v| !v.is_empty()),
                    scenario_nonce: None,
                    first_mes: Some(data_v2.first_mes.clone().into_bytes())
                        .filter(|v| !v.is_empty()),
                    first_mes_nonce: None,
                    mes_example: Some(data_v2.mes_example.clone().into_bytes())
                        .filter(|v| !v.is_empty()),
                    mes_example_nonce: None,
                    creator_notes: Some(data_v2.creator_notes.clone().into_bytes())
                        .filter(|v| !v.is_empty()),
                    creator_notes_nonce: None,
                    system_prompt: Some(data_v2.system_prompt.clone().into_bytes())
                        .filter(|v| !v.is_empty()),
                    system_prompt_nonce: None,
                    post_history_instructions: Some(
                        data_v2.post_history_instructions.clone().into_bytes(),
                    )
                    .filter(|v| !v.is_empty()),
                    post_history_instructions_nonce: None,
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
                    extensions: None, // Ensure extensions is None for V2 fallback
                    persona: None,
                    persona_nonce: None,
                    world_scenario: None,
                    world_scenario_nonce: None,
                    avatar: None,
                    chat: None,
                    greeting: None,
                    greeting_nonce: None,
                    definition: None,
                    definition_nonce: None,
                    default_voice: None,
                    category: None,
                    definition_visibility: None,
                    example_dialogue: None,
                    example_dialogue_nonce: None,
                    favorite: None,
                    first_message_visibility: None,
                    migrated_from: None,
                    model_prompt: None,
                    model_prompt_nonce: None,
                    model_prompt_visibility: None,
                    persona_visibility: None,
                    sharing_visibility: None,
                    status: None,
                    system_prompt_visibility: None,
                    system_tags: None,
                    token_budget: None,
                    usage_hints: None,
                    user_persona: None,
                    user_persona_nonce: None,
                    user_persona_visibility: None,
                    visibility: None,
                    world_scenario_visibility: None,
                    created_at: None,
                    updated_at: None,
                }
            }
        }
    }
}

#[derive(Queryable, Selectable, Identifiable, Associations, Serialize)]
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

impl std::fmt::Debug for CharacterAsset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CharacterAsset")
            .field("id", &self.id)
            .field("character_id", &self.character_id)
            .field("asset_type", &"[REDACTED]")
            .field("uri", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .field("ext", &self.ext)
            .finish()
    }
}

#[derive(Insertable)]
#[diesel(table_name = character_assets)]
pub struct NewCharacterAsset {
    #[diesel(serialize_as = Uuid)]
    pub character_id: Uuid, // Changed from i32
    pub asset_type: String, // Renamed from `type_`
    pub uri: String,
    pub name: String,
    pub ext: String,
}

impl std::fmt::Debug for NewCharacterAsset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewCharacterAsset")
            .field("character_id", &self.character_id)
            .field("asset_type", &"[REDACTED]")
            .field("uri", &"[REDACTED]")
            .field("name", &"[REDACTED]")
            .field("ext", &self.ext)
            .finish()
    }
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
        let content =
            "Line 1\n@@decorator1 value1\nLine 2\n@@decorator2\n@@@fallback2 val_fb\nLine 3";
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
        let content = "  @@ spaced_name   spaced value  \n\t@@@ spaced_fallback \t spaced_fb_value \t\nContent";
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

    // --- Tests for Default Implementations ---

    #[test]
    fn test_character_card_v3_default() {
        let card = CharacterCardV3::default();
        assert_eq!(card.spec, "");
        assert_eq!(card.spec_version, "");
        assert!(card.data.name.is_none()); // CharacterCardDataV3 default
    }

    #[test]
    fn test_character_card_data_v3_default() {
        let data = CharacterCardDataV3::default();
        assert!(data.name.is_none());
        assert_eq!(data.description, "");
        assert_eq!(data.personality, "");
        assert_eq!(data.scenario, "");
        assert_eq!(data.first_mes, "");
        assert_eq!(data.mes_example, "");
        assert_eq!(data.creator_notes, "");
        assert_eq!(data.system_prompt, "");
        assert_eq!(data.post_history_instructions, "");
        assert!(data.alternate_greetings.is_empty());
        assert!(data.tags.is_empty());
        assert_eq!(data.creator, "");
        assert_eq!(data.character_version, "");
        assert!(data.extensions.is_empty());
        assert!(data.character_book.is_none());
        assert!(data.assets.is_none());
        assert!(data.nickname.is_none());
        assert!(data.creator_notes_multilingual.is_none());
        assert!(data.source.is_none());
        assert!(data.group_only_greetings.is_empty());
        assert!(data.creation_date.is_none());
        assert!(data.modification_date.is_none());
    }

    #[test]
    fn test_new_character_default() {
        let new_char = NewCharacter::default();
        // user_id is not Default, so it won't be set here.
        // We are just testing the #[derive(Default)] part.
        assert_eq!(new_char.spec, "");
        assert_eq!(new_char.spec_version, "");
        assert_eq!(new_char.name, "");
        // Other fields are Option or Vec, default is None/empty
        assert!(new_char.description.is_none());
        assert!(new_char.personality.is_none());
        assert!(new_char.scenario.is_none());
        // ... etc for all Option fields
        assert!(new_char.extensions.is_none());
    }

    // --- Tests for Debug Implementations ---

    #[test]
    fn test_debug_format_does_not_panic() {
        // Test Debug impl for various structs by formatting them
        // We don't assert the exact output, just that formatting works.

        // V3 Card
        let card_v3 = CharacterCardV3::default();
        let _ = format!("{:?}", card_v3);
        let data_v3 = CharacterCardDataV3::default();
        let _ = format!("{:?}", data_v3);

        // Asset
        let asset = Asset {
            r#type: "image".to_string(),
            uri: "uri".to_string(),
            name: "name".to_string(),
            ext: "png".to_string(),
        };
        let _ = format!("{:?}", asset);

        // Decorator
        let decorator = Decorator {
            name: "test".to_string(),
            value: Some("value".to_string()),
            fallbacks: vec![],
        };
        let _ = format!("{:?}", decorator);

        // LorebookEntryPosition
        let pos = LorebookEntryPosition::BeforeChar;
        let _ = format!("{:?}", pos);

        // StandaloneLorebook
        let standalone_book = StandaloneLorebook {
            spec: "lorebook_v3".to_string(),
            data: Lorebook::default(),
        };
        let _ = format!("{:?}", standalone_book);

        // NewCharacter (needs user_id)
        let new_char = NewCharacter {
            user_id: Uuid::new_v4(),
            ..Default::default()
        };
        let _ = format!("{:?}", new_char);

        // CharacterAsset (needs id, character_id)
        let char_asset = CharacterAsset {
            id: 1,
            character_id: Uuid::new_v4(),
            asset_type: "image".to_string(),
            uri: "uri".to_string(),
            name: "name".to_string(),
            ext: "png".to_string(),
        };
        let _ = format!("{:?}", char_asset);

        // NewCharacterAsset (needs character_id)
        let new_char_asset = NewCharacterAsset {
            character_id: Uuid::new_v4(),
            asset_type: "image".to_string(),
            uri: "uri".to_string(),
            name: "name".to_string(),
            ext: "png".to_string(),
        };
        let _ = format!("{:?}", new_char_asset);
    }

    // --- Tests for NewCharacter::from_parsed_card (covering lines 433, 451, 457, 468, 471, 477-478, 528, 533) ---

    // Helper struct to simulate V2 data for testing V2Fallback path
    // In reality, this would likely be defined elsewhere if needed outside tests
    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    struct CharacterCardDataV2Sim {
        name: Option<String>,
        description: String,
        personality: String,
        scenario: String,
        first_mes: String,
        mes_example: String,
        creator_notes: String,
        system_prompt: String,
        post_history_instructions: String,
        alternate_greetings: Vec<String>,
        tags: Vec<String>,
        creator: String,
        character_version: String,
        // Add other V2 fields if necessary for more specific tests
    }

    #[test]
    fn test_from_parsed_card_v3_fields() {
        let user_id = Uuid::new_v4();
        let mut data_v3 = CharacterCardDataV3::default();
        data_v3.name = Some("Test V3".to_string());
        data_v3.tags = vec!["tag1".to_string(), "tag2".to_string()];
        data_v3.source = Some(vec!["source1".to_string()]);
        data_v3.group_only_greetings = vec!["group_greet1".to_string()];
        data_v3.creation_date = Some(1678886400); // Example timestamp
        data_v3.modification_date = Some(1678887400);
        data_v3.creator_notes_multilingual =
            Some(HashMap::from([("es".to_string(), "nota".to_string())]));
        data_v3.extensions =
            HashMap::from([("ext_key".to_string(), Value::String("ext_val".to_string()))]);

        let card_v3 = CharacterCardV3 {
            spec: "chara_card_v3".to_string(),
            spec_version: "3.0".to_string(),
            data: data_v3,
        };
        // Box the card data as expected by ParsedCharacterCard::V3
        // Pass the card directly, not boxed
        let parsed = ParsedCharacterCard::V3(card_v3);

        let new_char = NewCharacter::from_parsed_card(&parsed, user_id);

        assert_eq!(new_char.user_id, user_id);
        assert_eq!(new_char.name, "Test V3");
        assert_eq!(new_char.spec, "chara_card_v3");
        assert_eq!(new_char.spec_version, "3.0");

        // Test V3 Vec<String> -> Option<Vec<Option<String>>> conversion (lines 433, 451, 457)
        assert_eq!(
            new_char.tags,
            Some(vec![Some("tag1".to_string()), Some("tag2".to_string())])
        );
        assert_eq!(new_char.source, Some(vec![Some("source1".to_string())]));
        assert_eq!(
            new_char.group_only_greetings,
            Some(vec![Some("group_greet1".to_string())])
        );

        // Test timestamp conversion (lines 468, 471)
        assert!(new_char.creation_date.is_some());
        assert!(new_char.modification_date.is_some());
        assert_eq!(new_char.creation_date.unwrap().timestamp(), 1678886400);
        assert_eq!(new_char.modification_date.unwrap().timestamp(), 1678887400);

        // Test HashMap -> Json conversion (line 477-478 for multilingual, 481-489 for extensions)
        assert!(new_char.creator_notes_multilingual.is_some());
        let multi_notes_json = new_char.creator_notes_multilingual.unwrap().0; // Extract Value from Json wrapper
        assert!(multi_notes_json.is_object());
        assert_eq!(
            multi_notes_json.get("es").unwrap().as_str().unwrap(),
            "nota"
        );

        assert!(new_char.extensions.is_some());
        let extensions_json = new_char.extensions.unwrap().0; // Extract Value from Json wrapper
        assert!(extensions_json.is_object());
        assert_eq!(
            extensions_json.get("ext_key").unwrap().as_str().unwrap(),
            "ext_val"
        );
    }

    #[test]
    fn test_from_parsed_card_v2_fallback_fields() {
        let user_id = Uuid::new_v4();
        // Create a CharacterCardDataV3 instance populated with V2-like data
        let mut data_v2_as_v3 = CharacterCardDataV3::default();
        data_v2_as_v3.name = Some("Test V2".to_string());
        data_v2_as_v3.tags = vec!["v2tag1".to_string()];
        data_v2_as_v3.alternate_greetings = vec!["v2greet1".to_string()];
        // Populate other fields as needed if the V2Fallback variant expects them

        // Pass the V3 struct directly, not boxed
        let parsed = ParsedCharacterCard::V2Fallback(data_v2_as_v3);

        let new_char = NewCharacter::from_parsed_card(&parsed, user_id);

        assert_eq!(new_char.user_id, user_id);
        assert_eq!(new_char.name, "Test V2");
        assert_eq!(new_char.spec, "chara_card_v2_fallback"); // Check fallback spec
        assert_eq!(new_char.spec_version, "2.0"); // Check fallback version

        // Test V2 Vec<String> -> Option<Vec<Option<String>>> conversion (lines 528, 533)
        assert_eq!(new_char.tags, Some(vec![Some("v2tag1".to_string())]));
        assert_eq!(
            new_char.alternate_greetings,
            Some(vec![Some("v2greet1".to_string())])
        );

        // Check that V3 specific fields are None
        assert!(new_char.nickname.is_none());
        assert!(new_char.creator_notes_multilingual.is_none());
        assert!(new_char.source.is_none());
        assert!(new_char.group_only_greetings.is_none());
        assert!(new_char.creation_date.is_none());
        assert!(new_char.modification_date.is_none());
        assert!(new_char.extensions.is_none());
    }
    // TODO: Add other tests for character_card.rs structs/impls here if needed
}
