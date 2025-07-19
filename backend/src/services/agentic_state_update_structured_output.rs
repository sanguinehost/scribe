use serde::{Deserialize, Serialize};
use crate::errors::AppError;

/// Structured output schema for AgenticStateUpdateService relationship inference
/// Ensures AI generates valid JSON for relationship analysis

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipInferenceOutput {
    pub relationships: Vec<InferredRelationship>,
    pub confidence: f32,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredRelationship {
    pub from_entity: String,
    pub to_entity: String,
    pub relationship_type: String, // family|friend|romantic|enemy|professional|neutral
    pub strength: f32,
    pub evidence: String,
    pub changed: bool,
    pub change_reason: Option<String>,
}

/// Helper function to create the JSON schema for relationship inference
pub fn get_relationship_inference_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "relationships": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "from_entity": {
                            "type": "string",
                            "description": "Name of the entity the relationship is from"
                        },
                        "to_entity": {
                            "type": "string",
                            "description": "Name of the entity the relationship is to"
                        },
                        "relationship_type": {
                            "type": "string",
                            "enum": ["family", "friend", "romantic", "enemy", "professional", "neutral"],
                            "description": "Type of relationship between the entities"
                        },
                        "strength": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Strength of the relationship (0.0-1.0)"
                        },
                        "evidence": {
                            "type": "string",
                            "description": "Evidence supporting this relationship assessment"
                        },
                        "changed": {
                            "type": "boolean",
                            "description": "Whether the relationship has recently changed"
                        },
                        "change_reason": {
                            "type": "string",
                            "description": "Reason for the change (if changed=true)"
                        }
                    },
                    "required": ["from_entity", "to_entity", "relationship_type", "strength", "evidence", "changed"]
                },
                "description": "List of inferred relationships between entities"
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Overall confidence in the relationship analysis (0.0-1.0)"
            },
            "reasoning": {
                "type": "string",
                "description": "Explanation of the relationship analysis"
            }
        },
        "required": ["relationships", "confidence", "reasoning"]
    })
}

/// Convert structured output to internal types used by AgenticStateUpdateService
impl RelationshipInferenceOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate confidence is within range
        if self.confidence < 0.0 || self.confidence > 1.0 {
            return Err(AppError::InvalidInput(
                format!("Confidence must be between 0.0 and 1.0, got: {}", self.confidence)
            ));
        }
        
        // Validate each relationship
        for relationship in &self.relationships {
            // Validate strength
            if relationship.strength < 0.0 || relationship.strength > 1.0 {
                return Err(AppError::InvalidInput(
                    format!("Relationship strength must be between 0.0 and 1.0, got: {}", relationship.strength)
                ));
            }
            
            // Validate relationship type
            let valid_types = ["family", "friend", "romantic", "enemy", "professional", "neutral"];
            if !valid_types.contains(&relationship.relationship_type.as_str()) {
                return Err(AppError::InvalidInput(
                    format!("Invalid relationship type: {}", relationship.relationship_type)
                ));
            }
            
            // Validate change_reason is provided when changed=true
            if relationship.changed && relationship.change_reason.is_none() {
                return Err(AppError::InvalidInput(
                    "change_reason must be provided when changed=true".to_string()
                ));
            }
            
            // Validate entity names are not empty
            if relationship.from_entity.trim().is_empty() || relationship.to_entity.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Entity names cannot be empty".to_string()
                ));
            }
            
            // Validate evidence is not empty
            if relationship.evidence.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Evidence cannot be empty".to_string()
                ));
            }
        }
        
        // Validate reasoning is not empty
        if self.reasoning.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Reasoning cannot be empty".to_string()
            ));
        }
        
        Ok(())
    }
}

/// Structured output for spatial inference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialInferenceOutput {
    pub primary_location: Option<String>,
    pub entities_present: Vec<EntityPresent>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityPresent {
    pub entity_id: String,
    pub entity_name: String,
}

/// Helper function to create the JSON schema for spatial inference
pub fn get_spatial_inference_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "primary_location": {
                "type": ["string", "null"],
                "description": "The primary location identified from context"
            },
            "entities_present": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_id": {
                            "type": "string",
                            "description": "UUID of the entity"
                        },
                        "entity_name": {
                            "type": "string",
                            "description": "Name of the entity"
                        }
                    },
                    "required": ["entity_id", "entity_name"]
                },
                "description": "List of entities present at the location"
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Confidence in the spatial analysis (0.0-1.0)"
            }
        },
        "required": ["primary_location", "entities_present", "confidence"]
    })
}

impl SpatialInferenceOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate confidence is within range
        if self.confidence < 0.0 || self.confidence > 1.0 {
            return Err(AppError::InvalidInput(
                format!("Confidence must be between 0.0 and 1.0, got: {}", self.confidence)
            ));
        }
        
        // Validate entity IDs are valid UUIDs
        for entity in &self.entities_present {
            if entity.entity_id.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Entity ID cannot be empty".to_string()
                ));
            }
            
            // Try to parse as UUID
            if uuid::Uuid::parse_str(&entity.entity_id).is_err() {
                return Err(AppError::InvalidInput(
                    format!("Invalid UUID format for entity_id: {}", entity.entity_id)
                ));
            }
            
            if entity.entity_name.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Entity name cannot be empty".to_string()
                ));
            }
        }
        
        Ok(())
    }
}