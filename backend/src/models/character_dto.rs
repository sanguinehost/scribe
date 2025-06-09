// backend/src/models/character_dto.rs

use diesel_json::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// DTO for character creation requests
#[derive(Debug, Serialize, Deserialize)]
pub struct CharacterCreateDto {
    // Required fields (minimum from a user experience perspective)
    pub name: Option<String>,
    pub description: Option<String>,
    pub first_mes: Option<String>,

    // Optional fields that mirror CharacterCardDataV3 structure
    #[serde(default)]
    pub personality: String,
    #[serde(default)]
    pub scenario: String,
    #[serde(default)]
    pub mes_example: String,
    #[serde(default)]
    pub creator_notes: String,
    #[serde(default)]
    pub system_prompt: String,
    #[serde(default)]
    pub post_history_instructions: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub creator: String,
    #[serde(default)]
    pub character_version: String,
    #[serde(default)]
    pub alternate_greetings: Vec<String>,
    #[serde(default)]
    pub creator_notes_multilingual: Option<Json<JsonValue>>,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub source: Option<Vec<String>>,
    #[serde(default)]
    pub group_only_greetings: Vec<String>,
    #[serde(default)]
    pub creation_date: Option<i64>,
    #[serde(default)]
    pub modification_date: Option<i64>,
    #[serde(default)]
    pub extensions: Option<Json<JsonValue>>,

    // SillyTavern v3 fields
    #[serde(default)]
    pub fav: Option<bool>,
    #[serde(default)]
    pub world: Option<String>,
    #[serde(default)]
    pub creator_comment: Option<String>,
    #[serde(default)]
    pub depth_prompt: Option<String>,
    #[serde(default)]
    pub depth_prompt_depth: Option<i32>,
    #[serde(default)]
    pub depth_prompt_role: Option<String>,
}

/// DTO for character update requests
/// All fields are optional to allow partial updates
#[derive(Debug, Serialize, Deserialize)]
pub struct CharacterUpdateDto {
    pub name: Option<String>,
    pub description: Option<String>,
    pub personality: Option<String>,
    pub scenario: Option<String>,
    pub first_mes: Option<String>,
    pub mes_example: Option<String>,
    pub creator_notes: Option<String>,
    pub system_prompt: Option<String>,
    pub post_history_instructions: Option<String>,
    pub tags: Option<Vec<String>>,
    pub creator: Option<String>,
    pub character_version: Option<String>,
    pub alternate_greetings: Option<Vec<String>>,
    pub creator_notes_multilingual: Option<Json<JsonValue>>,
    pub nickname: Option<String>,
    pub source: Option<Vec<String>>,
    pub group_only_greetings: Option<Vec<String>>,
    pub creation_date: Option<i64>,
    pub modification_date: Option<i64>,
    pub extensions: Option<Json<JsonValue>>,

    // SillyTavern v3 fields
    pub fav: Option<bool>,
    pub world: Option<String>,
    pub creator_comment: Option<String>,
    pub depth_prompt: Option<String>,
    pub depth_prompt_depth: Option<i32>,
    pub depth_prompt_role: Option<String>,
}

impl CharacterCreateDto {
    /// Validates that all required fields are provided and not empty
    ///
    /// # Errors
    /// Returns a string with validation errors if:
    /// - Name is None or empty
    /// - Description is None or empty  
    /// - First message is None or empty
    pub fn validate(&self) -> Result<(), String> {
        let mut errors = Vec::new();

        match &self.name {
            Some(name_val) if name_val.trim().is_empty() => {
                errors.push("name cannot be empty if provided".to_string());
            }
            None => {
                errors.push("name is required".to_string());
            }
            _ => {}
        }

        match &self.description {
            Some(desc_val) if desc_val.trim().is_empty() => {
                errors.push("description cannot be empty if provided".to_string());
            }
            None => {
                errors.push("description is required".to_string());
            }
            _ => {}
        }

        match &self.first_mes {
            Some(fm_val) if fm_val.trim().is_empty() => {
                errors.push("first_mes cannot be empty if provided".to_string());
            }
            None => {
                errors.push("first_mes is required".to_string());
            }
            _ => {}
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!("Validation errors: {}", errors.join(", ")))
        }
    }
}
