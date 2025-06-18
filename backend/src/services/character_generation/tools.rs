use serde::Deserialize;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::{
    AppState,
    errors::AppError,
};

use super::{
    types::*,
    field_generator::FieldGenerator,
    full_character_generator::FullCharacterGenerator,
    enhancement_service::EnhancementService,
};

/// Character generation tool for ScribeAssistant mode
pub struct CharacterGenerationTool {
    field_generator: FieldGenerator,
    full_character_generator: FullCharacterGenerator,
    enhancement_service: EnhancementService,
}

impl CharacterGenerationTool {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            field_generator: FieldGenerator::new(state.clone()),
            full_character_generator: FullCharacterGenerator::new(state.clone()),
            enhancement_service: EnhancementService::new(state),
        }
    }

    /// Execute a character generation tool call
    #[instrument(skip_all, fields(tool_name = %call.tool_name))]
    pub async fn execute_tool_call(&self, call: CharacterGenerationToolCall, user_id: uuid::Uuid) -> Result<CharacterGenerationToolResponse, AppError> {
        info!("Executing character generation tool: {}", call.tool_name);

        let result = match call.tool_name.as_str() {
            "generate_character_field" => self.handle_generate_field(call.parameters, user_id).await,
            "create_full_character" => self.handle_create_character(call.parameters, user_id).await,
            "enhance_character_field" => self.handle_enhance_field(call.parameters, user_id).await,
            "analyze_character_style" => self.handle_analyze_style(call.parameters).await,
            _ => Err(AppError::InvalidInput(
                format!("Unknown tool: {}", call.tool_name)
            )),
        };

        match result {
            Ok(value) => Ok(CharacterGenerationToolResponse {
                success: true,
                result: Some(value),
                error: None,
                request_id: call.request_id,
            }),
            Err(error) => Ok(CharacterGenerationToolResponse {
                success: false,
                result: None,
                error: Some(error.to_string()),
                request_id: call.request_id,
            }),
        }
    }

    /// Handle field generation tool call
    async fn handle_generate_field(&self, parameters: serde_json::Value, user_id: uuid::Uuid) -> Result<serde_json::Value, AppError> {
        let request: FieldGenerationRequest = serde_json::from_value(parameters)
            .map_err(|e| AppError::InvalidInput(format!("Invalid field generation parameters: {}", e)))?;

        let result = self.field_generator.generate_field(request, user_id).await?;
        Ok(serde_json::to_value(result)?)
    }

    /// Handle full character creation tool call
    async fn handle_create_character(&self, parameters: serde_json::Value, user_id: uuid::Uuid) -> Result<serde_json::Value, AppError> {
        let request: FullCharacterRequest = serde_json::from_value(parameters)
            .map_err(|e| AppError::InvalidInput(format!("Invalid character creation parameters: {}", e)))?;

        let result = self.full_character_generator.generate_character(request, user_id).await?;
        Ok(serde_json::to_value(result)?)
    }

    /// Handle field enhancement tool call
    async fn handle_enhance_field(&self, parameters: serde_json::Value, user_id: uuid::Uuid) -> Result<serde_json::Value, AppError> {
        let request: EnhancementRequest = serde_json::from_value(parameters)
            .map_err(|e| AppError::InvalidInput(format!("Invalid enhancement parameters: {}", e)))?;

        let result = self.enhancement_service.enhance_field(request, user_id).await?;
        Ok(serde_json::to_value(result)?)
    }

    /// Handle style analysis tool call
    async fn handle_analyze_style(&self, parameters: serde_json::Value) -> Result<serde_json::Value, AppError> {
        #[derive(Deserialize)]
        struct StyleAnalysisParams {
            content: String,
        }

        let params: StyleAnalysisParams = serde_json::from_value(parameters)
            .map_err(|e| AppError::InvalidInput(format!("Invalid style analysis parameters: {}", e)))?;

        // Simplified style analysis - could be enhanced with ML or more sophisticated analysis
        let detected_style = self.detect_style(&params.content);
        let confidence = self.calculate_confidence(&params.content, &detected_style);
        let indicators = self.get_style_indicators(&params.content, &detected_style);

        let result = serde_json::json!({
            "detected_style": detected_style,
            "confidence": confidence,
            "style_indicators": indicators,
            "recommendations": self.get_style_recommendations(&detected_style)
        });

        Ok(result)
    }

    /// Detect the style of given content
    fn detect_style(&self, content: &str) -> DescriptionStyle {
        // Simple heuristic-based style detection
        if content.contains("{{char}}") || content.contains("{{user}}") {
            if content.contains("will") && content.contains("response") {
                return DescriptionStyle::System;
            } else {
                return DescriptionStyle::Worldbuilding;
            }
        }

        if content.contains("Characters(") {
            return DescriptionStyle::Group;
        }

        if content.contains("Name:") || content.contains("Age:") || content.contains("Height:") {
            return DescriptionStyle::Profile;
        }

        // Check for narrative vs traits based on sentence structure
        let sentences: Vec<&str> = content.split(['.', '!', '?']).collect();
        let short_sentences = sentences.iter().filter(|s| s.len() < 50).count();
        let total_sentences = sentences.len();

        if total_sentences > 0 && (short_sentences as f32 / total_sentences as f32) > 0.7 {
            DescriptionStyle::Traits
        } else {
            DescriptionStyle::Narrative
        }
    }

    /// Calculate confidence in style detection
    fn calculate_confidence(&self, content: &str, detected_style: &DescriptionStyle) -> f32 {
        // Simplified confidence calculation
        match detected_style {
            DescriptionStyle::System | DescriptionStyle::Worldbuilding => {
                if content.contains("{{char}}") || content.contains("{{user}}") {
                    0.9
                } else {
                    0.3
                }
            },
            DescriptionStyle::Group => {
                if content.contains("Characters(") {
                    0.95
                } else {
                    0.1
                }
            },
            DescriptionStyle::Profile => {
                let field_indicators = ["Name:", "Age:", "Height:", "Weight:"];
                let matches = field_indicators.iter().filter(|&&indicator| content.contains(indicator)).count();
                (matches as f32 / field_indicators.len() as f32).min(0.9)
            },
            DescriptionStyle::Traits => 0.6, // Default medium confidence
            DescriptionStyle::Narrative => 0.7,
            DescriptionStyle::Auto => 0.1,
        }
    }

    /// Get style indicators for the detected style
    fn get_style_indicators(&self, content: &str, detected_style: &DescriptionStyle) -> Vec<String> {
        let mut indicators = Vec::new();

        match detected_style {
            DescriptionStyle::System | DescriptionStyle::Worldbuilding => {
                if content.contains("{{char}}") {
                    indicators.push("Contains {{char}} placeholders".to_string());
                }
                if content.contains("{{user}}") {
                    indicators.push("Contains {{user}} placeholders".to_string());
                }
            },
            DescriptionStyle::Group => {
                if content.contains("Characters(") {
                    indicators.push("Uses Characters() format".to_string());
                }
            },
            DescriptionStyle::Profile => {
                let fields = ["Name:", "Age:", "Height:", "Weight:"];
                for field in fields {
                    if content.contains(field) {
                        indicators.push(format!("Contains {} field", field));
                    }
                }
            },
            DescriptionStyle::Traits => {
                indicators.push("Short, punchy sentences".to_string());
            },
            DescriptionStyle::Narrative => {
                indicators.push("Flowing prose style".to_string());
            },
            DescriptionStyle::Auto => {},
        }

        indicators
    }

    /// Get recommendations for improving content in the detected style
    fn get_style_recommendations(&self, detected_style: &DescriptionStyle) -> Vec<String> {
        match detected_style {
            DescriptionStyle::Traits => vec![
                "Consider adding more specific physical details".to_string(),
                "Use more sentence fragments for impact".to_string(),
            ],
            DescriptionStyle::Narrative => vec![
                "Add more sensory details".to_string(),
                "Develop the character's background further".to_string(),
            ],
            DescriptionStyle::Profile => vec![
                "Ensure all key fields are filled".to_string(),
                "Add personality section after biographical data".to_string(),
            ],
            DescriptionStyle::Group => vec![
                "Define relationships between characters".to_string(),
                "Ensure each character has distinct traits".to_string(),
            ],
            DescriptionStyle::Worldbuilding => vec![
                "Expand on the world lore".to_string(),
                "Add more context about the character's role".to_string(),
            ],
            DescriptionStyle::System => vec![
                "Clarify behavioral boundaries".to_string(),
                "Add more specific interaction guidelines".to_string(),
            ],
            DescriptionStyle::Auto => vec![],
        }
    }

    /// Get available tool definitions for ScribeAssistant
    pub fn get_tool_definitions() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "name": "generate_character_field",
                "description": "Generate a specific field for a character (description, personality, etc.)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "field": {
                            "type": "string",
                            "enum": ["description", "personality", "first_mes", "scenario", "mes_example", "system_prompt", "depth_prompt", "tags"],
                            "description": "The character field to generate"
                        },
                        "style": {
                            "type": "string",
                            "enum": ["traits", "narrative", "profile", "group", "worldbuilding", "system", "auto"],
                            "description": "The style to use for generation"
                        },
                        "user_prompt": {
                            "type": "string",
                            "description": "Description of what the user wants generated"
                        },
                        "character_context": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "description": {"type": "string"},
                                "personality": {"type": "string"},
                                "scenario": {"type": "string"},
                                "tags": {"type": "array", "items": {"type": "string"}}
                            },
                            "description": "Existing character information for context"
                        }
                    },
                    "required": ["field", "user_prompt"]
                }
            }),
            serde_json::json!({
                "name": "create_full_character",
                "description": "Create a complete character from a concept description",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "concept": {
                            "type": "string",
                            "description": "Description of the character concept to generate"
                        },
                        "style_preferences": {
                            "type": "object",
                            "properties": {
                                "description_style": {
                                    "type": "string",
                                    "enum": ["traits", "narrative", "profile", "group", "worldbuilding", "system", "auto"]
                                },
                                "tone": {"type": "string"},
                                "length": {"type": "string"},
                                "focus": {"type": "string"}
                            }
                        }
                    },
                    "required": ["concept"]
                }
            }),
            serde_json::json!({
                "name": "enhance_character_field",
                "description": "Improve existing character field content",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "field": {
                            "type": "string",
                            "enum": ["description", "personality", "first_mes", "scenario", "mes_example", "system_prompt", "depth_prompt", "tags"]
                        },
                        "current_content": {
                            "type": "string",
                            "description": "The existing content to enhance"
                        },
                        "enhancement_instructions": {
                            "type": "string",
                            "description": "Instructions for how to improve the content"
                        },
                        "character_context": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "description": {"type": "string"},
                                "personality": {"type": "string"},
                                "scenario": {"type": "string"},
                                "tags": {"type": "array", "items": {"type": "string"}}
                            }
                        }
                    },
                    "required": ["field", "current_content", "enhancement_instructions"]
                }
            })
        ]
    }
}