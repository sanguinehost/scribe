use serde::{Deserialize, Serialize};
use crate::errors::AppError;
use super::types::*;

/// Structured output schemas for different generation types
/// These will be used with rust-genai structured output capabilities

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterFieldOutput {
    pub content: String,
    pub reasoning: Option<String>, // Why this content was generated
    pub style_applied: String,
    pub quality_score: Option<f32>, // Self-assessment of quality (1-10)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullCharacterOutput {
    pub name: String,
    pub description: String,
    pub personality: String,
    pub scenario: String,
    pub first_mes: String,
    pub mes_example: Option<String>,
    pub system_prompt: Option<String>,
    pub depth_prompt: Option<String>,
    pub tags: Vec<String>,
    pub reasoning: Option<String>, // Overall reasoning for character design
    pub character_summary: Option<String>, // Brief summary of the character concept
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancementOutput {
    pub enhanced_content: String,
    pub changes_made: Vec<String>,
    pub improvement_reasoning: String,
    pub quality_improvement: Option<f32>, // How much better it is (1-10)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StyleAnalysisOutput {
    pub detected_style: DescriptionStyle,
    pub confidence: f32, // 0.0 - 1.0
    pub style_indicators: Vec<String>, // What features indicated this style
    pub recommendations: Vec<String>, // Suggestions for improvement
}

/// Validation functions for structured outputs
impl CharacterFieldOutput {
    pub fn validate(&self, field: &CharacterField) -> Result<(), AppError> {
        if self.content.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Generated content cannot be empty".to_string()
            ));
        }

        // Field-specific validation
        match field {
            CharacterField::Tags => {
                // For tags, content should be comma-separated or JSON array
                if !self.content.contains(',') && !self.content.starts_with('[') {
                    return Err(AppError::InvalidInput(
                        "Tags field should contain comma-separated values or JSON array".to_string()
                    ));
                }
            },
            CharacterField::FirstMes => {
                // First message should be substantial
                if self.content.len() < 20 {
                    return Err(AppError::InvalidInput(
                        "First message should be at least 20 characters".to_string()
                    ));
                }
            },
            CharacterField::AlternateGreeting => {
                // Alternate greeting should be substantial
                if self.content.len() < 20 {
                    return Err(AppError::InvalidInput(
                        "Alternate greeting should be at least 20 characters".to_string()
                    ));
                }
            },
            _ => {} // Other fields have more flexible requirements
        }

        Ok(())
    }
}

impl FullCharacterOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.name.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Character name cannot be empty".to_string()
            ));
        }

        if self.description.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Character description cannot be empty".to_string()
            ));
        }

        if self.first_mes.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "First message cannot be empty".to_string()
            ));
        }

        if self.first_mes.len() < 20 {
            return Err(AppError::InvalidInput(
                "First message should be at least 20 characters".to_string()
            ));
        }

        Ok(())
    }
}

/// Remove additionalProperties from a schema (for Gemini compatibility)
fn remove_additional_properties(mut schema: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = schema.as_object_mut() {
        obj.remove("additionalProperties");
        
        // Recursively process nested objects
        if let Some(properties) = obj.get_mut("properties") {
            if let Some(props_obj) = properties.as_object_mut() {
                for (_, prop_value) in props_obj.iter_mut() {
                    *prop_value = remove_additional_properties(prop_value.clone());
                }
            }
        }
        
        // Process array items
        if let Some(items) = obj.get_mut("items") {
            *items = remove_additional_properties(items.clone());
        }
    }
    schema
}

/// Helper functions for creating JSON schemas for structured output
pub fn get_field_generation_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "content": {
                "type": "string",
                "description": "The generated content for the character field"
            },
            "reasoning": {
                "type": "string",
                "description": "Explanation of why this content was generated and how it fits the character"
            },
            "style_applied": {
                "type": "string",
                "description": "The style that was applied during generation"
            },
            "quality_score": {
                "type": "number",
                "minimum": 1,
                "maximum": 10,
                "description": "Self-assessment of content quality from 1-10"
            }
        },
        "required": ["content", "style_applied"],
        "additionalProperties": false
    })
}

/// Get Gemini-compatible field generation schema (without additionalProperties)
pub fn get_field_generation_schema_gemini() -> serde_json::Value {
    let schema = get_field_generation_schema();
    remove_additional_properties(schema)
}

pub fn get_full_character_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "description": "Character's name"
            },
            "description": {
                "type": "string",
                "description": "Detailed character description"
            },
            "personality": {
                "type": "string",
                "description": "Character's personality traits and quirks"
            },
            "scenario": {
                "type": "string",
                "description": "Setting or scenario where character exists"
            },
            "first_mes": {
                "type": "string",
                "description": "Character's first message to start conversations"
            },
            "mes_example": {
                "type": "string",
                "description": "Example dialogue showing how character speaks"
            },
            "system_prompt": {
                "type": "string",
                "description": "Instructions for how AI should portray this character"
            },
            "depth_prompt": {
                "type": "string",
                "description": "Additional character depth and background notes"
            },
            "tags": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Tags describing character traits, themes, or categories"
            },
            "reasoning": {
                "type": "string",
                "description": "Explanation of the character design choices"
            },
            "character_summary": {
                "type": "string",
                "description": "Brief summary of the character concept"
            }
        },
        "required": ["name", "description", "first_mes", "tags"],
        "additionalProperties": false
    })
}

/// Get Gemini-compatible full character schema (without additionalProperties)
pub fn get_full_character_schema_gemini() -> serde_json::Value {
    let schema = get_full_character_schema();
    remove_additional_properties(schema)
}

pub fn get_enhancement_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "enhanced_content": {
                "type": "string",
                "description": "The improved version of the content"
            },
            "changes_made": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "List of specific improvements made"
            },
            "improvement_reasoning": {
                "type": "string",
                "description": "Explanation of why these improvements were made"
            },
            "quality_improvement": {
                "type": "number",
                "minimum": 1,
                "maximum": 10,
                "description": "Assessment of how much the content was improved"
            }
        },
        "required": ["enhanced_content", "changes_made", "improvement_reasoning"],
        "additionalProperties": false
    })
}

/// Get Gemini-compatible enhancement schema (without additionalProperties)
pub fn get_enhancement_schema_gemini() -> serde_json::Value {
    let schema = get_enhancement_schema();
    remove_additional_properties(schema)
}

pub fn get_style_analysis_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "detected_style": {
                "type": "string",
                "enum": ["traits", "narrative", "profile", "group", "worldbuilding", "system"],
                "description": "The detected description style"
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Confidence level in the style detection"
            },
            "style_indicators": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Features that indicated this style"
            },
            "recommendations": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Suggestions for improving the content"
            }
        },
        "required": ["detected_style", "confidence"],
        "additionalProperties": false
    })
}

/// Get Gemini-compatible style analysis schema (without additionalProperties)
pub fn get_style_analysis_schema_gemini() -> serde_json::Value {
    let schema = get_style_analysis_schema();
    remove_additional_properties(schema)
}