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
}

/// DTO for character field override in a specific chat session
#[derive(Debug, Serialize, Deserialize)]
pub struct CharacterOverrideDto {
    /// The name of the field to override (e.g., "description", "personality", "first_mes")
    pub field_name: String,
    
    /// The new value for the field, specific to this chat session
    pub value: String,
}

impl CharacterCreateDto {
    /// Validates that all required fields are provided and not empty
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

impl CharacterOverrideDto {
    /// Validates that the field name is valid and supported for overrides
    pub fn validate(&self) -> Result<(), String> {
        // Initially supporting these fields as per plan
        let supported_fields = ["description", "personality", "first_mes"];
        
        if self.field_name.trim().is_empty() {
            return Err("field_name is required".to_string());
        }
        
        if self.value.trim().is_empty() {
            return Err("value is required".to_string());
        }
        
        if !supported_fields.contains(&self.field_name.as_str()) {
            return Err(format!(
                "field_name '{}' is not supported for overrides. Supported fields: {}", 
                self.field_name, 
                supported_fields.join(", ")
            ));
        }
        
        Ok(())
    }
}