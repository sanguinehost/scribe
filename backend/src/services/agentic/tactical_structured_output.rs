use serde::{Deserialize, Serialize};
use crate::errors::AppError;

/// Structured output schema for Tactical Agent (Stage Manager layer)
/// Ensures AI generates valid enriched context with proper types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticalEnrichmentOutput {
    pub immediate_focus: String, // What the tactical agent should focus on
    pub relevant_world_elements: Vec<WorldElementOutput>, // World elements to consider
    pub character_relationships: Vec<CharacterRelationshipOutput>, // Active relationships
    pub environmental_factors: Vec<String>, // Environmental considerations
    pub available_actions: Vec<String>, // Actions the character could take
    pub hidden_information: Vec<String>, // Information known to AI but not character
    pub narrative_constraints: Vec<String>, // Constraints to respect
    pub opportunity_spaces: Vec<String>, // Opportunities for interesting developments
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldElementOutput {
    pub element_name: String,
    pub element_type: String, // "location", "object", "npc", "concept"
    pub relevance: String, // Why this element matters now
    pub interaction_potential: String, // How it could be interacted with
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharacterRelationshipOutput {
    pub character_name: String,
    pub relationship_type: String, // "ally", "rival", "neutral", "romantic", "family"
    pub current_status: String, // Current state of the relationship
    pub emotional_weight: String, // How important this relationship is
}

/// Helper function to create the JSON schema for tactical enrichment
pub fn get_tactical_enrichment_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "immediate_focus": {
                "type": "string",
                "description": "The immediate narrative focus based on strategic directive and world state"
            },
            "relevant_world_elements": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "element_name": {
                            "type": "string",
                            "description": "Name of the world element"
                        },
                        "element_type": {
                            "type": "string",
                            "enum": ["location", "object", "npc", "concept"],
                            "description": "Type of world element"
                        },
                        "relevance": {
                            "type": "string",
                            "description": "Why this element matters in the current context"
                        },
                        "interaction_potential": {
                            "type": "string",
                            "description": "How the character could interact with this element"
                        }
                    },
                    "required": ["element_name", "element_type", "relevance", "interaction_potential"]
                },
                "description": "World elements relevant to the current scene"
            },
            "character_relationships": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "character_name": {
                            "type": "string",
                            "description": "Name of the related character"
                        },
                        "relationship_type": {
                            "type": "string",
                            "enum": ["ally", "rival", "neutral", "romantic", "family", "mentor", "student", "colleague", "enemy"],
                            "description": "Type of relationship"
                        },
                        "current_status": {
                            "type": "string",
                            "description": "Current state of the relationship"
                        },
                        "emotional_weight": {
                            "type": "string",
                            "description": "Importance of this relationship to the character"
                        }
                    },
                    "required": ["character_name", "relationship_type", "current_status", "emotional_weight"]
                },
                "description": "Active character relationships"
            },
            "environmental_factors": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Environmental factors affecting the scene (weather, time, atmosphere)"
            },
            "available_actions": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Concrete actions the character could take"
            },
            "hidden_information": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Information known to the AI but not the character"
            },
            "narrative_constraints": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Constraints to respect (character limitations, world rules)"
            },
            "opportunity_spaces": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Opportunities for interesting narrative developments"
            }
        },
        "required": [
            "immediate_focus",
            "relevant_world_elements",
            "character_relationships",
            "environmental_factors",
            "available_actions",
            "hidden_information",
            "narrative_constraints",
            "opportunity_spaces"
        ]
    })
}

/// Convert structured output to internal EnrichedContext type
impl TacticalEnrichmentOutput {
    pub fn to_enriched_context(&self) -> Result<crate::services::agentic::types::EnrichedContext, AppError> {
        use crate::services::agentic::types::{EnrichedContext, WorldElement, CharacterRelationship};
        
        // Convert world elements
        let mut world_elements = Vec::new();
        for element in &self.relevant_world_elements {
            world_elements.push(WorldElement {
                element_name: element.element_name.clone(),
                element_type: element.element_type.clone(),
                relevance: element.relevance.clone(),
                interaction_potential: element.interaction_potential.clone(),
            });
        }
        
        // Convert character relationships
        let mut relationships = Vec::new();
        for rel in &self.character_relationships {
            relationships.push(CharacterRelationship {
                character_name: rel.character_name.clone(),
                relationship_type: rel.relationship_type.clone(),
                current_status: rel.current_status.clone(),
                emotional_weight: rel.emotional_weight.clone(),
            });
        }
        
        Ok(EnrichedContext {
            immediate_focus: self.immediate_focus.clone(),
            relevant_world_elements: world_elements,
            character_relationships: relationships,
            environmental_factors: self.environmental_factors.clone(),
            available_actions: self.available_actions.clone(),
            hidden_information: self.hidden_information.clone(),
            narrative_constraints: self.narrative_constraints.clone(),
            opportunity_spaces: self.opportunity_spaces.clone(),
        })
    }
}

/// Validation for structured output
impl TacticalEnrichmentOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        // Validate immediate focus
        if self.immediate_focus.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Immediate focus cannot be empty".to_string()
            ));
        }
        
        // Validate world elements
        if self.relevant_world_elements.is_empty() {
            return Err(AppError::InvalidInput(
                "At least one relevant world element is required".to_string()
            ));
        }
        
        for element in &self.relevant_world_elements {
            if element.element_name.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "World element name cannot be empty".to_string()
                ));
            }
            
            let valid_types = ["location", "object", "npc", "concept"];
            if !valid_types.contains(&element.element_type.as_str()) {
                return Err(AppError::InvalidInput(
                    format!("Invalid element type: {}", element.element_type)
                ));
            }
        }
        
        // Validate character relationships
        for rel in &self.character_relationships {
            if rel.character_name.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Character name in relationship cannot be empty".to_string()
                ));
            }
            
            let valid_relationship_types = [
                "ally", "rival", "neutral", "romantic", "family", 
                "mentor", "student", "colleague", "enemy"
            ];
            if !valid_relationship_types.contains(&rel.relationship_type.as_str()) {
                return Err(AppError::InvalidInput(
                    format!("Invalid relationship type: {}", rel.relationship_type)
                ));
            }
        }
        
        // Ensure we have at least some content in arrays
        if self.available_actions.is_empty() {
            return Err(AppError::InvalidInput(
                "At least one available action is required".to_string()
            ));
        }
        
        if self.opportunity_spaces.is_empty() {
            return Err(AppError::InvalidInput(
                "At least one opportunity space is required".to_string()
            ));
        }
        
        Ok(())
    }
}