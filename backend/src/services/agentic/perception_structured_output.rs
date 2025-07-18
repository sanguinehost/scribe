use serde::{Deserialize, Serialize};

/// Structured output schema for Perception Agent pre-response analysis
/// Ensures AI generates valid entity extraction with proper types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerceptionEntityExtractionOutput {
    pub entities: Vec<ExtractedEntity>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedEntity {
    pub name: String,
    pub entity_type: String,
    pub relevance_score: f32,
    pub context_notes: Option<String>,
}

/// Structured output for hierarchy analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchyAnalysisOutput {
    pub hierarchy_insights: Vec<HierarchyInsightOutput>,
    pub spatial_relationships: Vec<SpatialRelationshipOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchyInsightOutput {
    pub entity_name: String,
    pub hierarchy_depth: i32,
    pub parent_entity: Option<String>,
    pub child_entities: Vec<String>,
    pub insight: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialRelationshipOutput {
    pub entity_a: String,
    pub entity_b: String,
    pub relationship_type: String,
    pub distance: Option<String>,
}

/// Structured output for salience updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SalienceUpdateOutput {
    pub updates: Vec<EntitySalienceUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySalienceUpdate {
    pub entity_name: String,
    pub previous_tier: Option<String>,
    pub new_tier: String,
    pub reasoning: String,
    pub confidence: f32,
}

/// Helper function to create the JSON schema for entity extraction
pub fn get_entity_extraction_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "entities": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "The name of the entity (character, location, object, concept)"
                        },
                        "entity_type": {
                            "type": "string",
                            "enum": ["character", "location", "object", "organization"],
                            "description": "The type of ECS entity - character (people, NPCs, beings), location (places, regions, buildings), object (items, artifacts, tools), organization (groups, factions, guilds). Events are not entities in ECS."
                        },
                        "relevance_score": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "How relevant this entity is to the current conversation (0.0-1.0)"
                        },
                        "context_notes": {
                            "type": "string",
                            "description": "Optional notes about the entity's context or significance"
                        }
                    },
                    "required": ["name", "entity_type", "relevance_score"]
                },
                "description": "List of entities found in the conversation context"
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Overall confidence in the entity extraction (0.0-1.0)"
            }
        },
        "required": ["entities", "confidence"]
    })
}

/// Helper function to create the JSON schema for hierarchy analysis
pub fn get_hierarchy_analysis_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "hierarchy_insights": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_name": {
                            "type": "string",
                            "description": "Name of the entity in the hierarchy"
                        },
                        "hierarchy_depth": {
                            "type": "integer",
                            "description": "Depth level in the hierarchy (0 = root)"
                        },
                        "parent_entity": {
                            "type": "string",
                            "description": "Name of the parent entity, if any"
                        },
                        "child_entities": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "Names of child entities"
                        },
                        "insight": {
                            "type": "string",
                            "description": "Narrative insight about this entity's position in the hierarchy"
                        }
                    },
                    "required": ["entity_name", "hierarchy_depth", "child_entities", "insight"]
                }
            },
            "spatial_relationships": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_a": {
                            "type": "string",
                            "description": "First entity in the relationship"
                        },
                        "entity_b": {
                            "type": "string",
                            "description": "Second entity in the relationship"
                        },
                        "relationship_type": {
                            "type": "string",
                            "enum": ["contains", "near", "adjacent_to", "connected_to", "part_of", "overlaps"],
                            "description": "Type of spatial relationship"
                        },
                        "distance": {
                            "type": "string",
                            "description": "Optional distance or proximity description"
                        }
                    },
                    "required": ["entity_a", "entity_b", "relationship_type"]
                }
            }
        },
        "required": ["hierarchy_insights", "spatial_relationships"]
    })
}

/// Helper function to create the JSON schema for salience updates
pub fn get_salience_update_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "updates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_name": {
                            "type": "string",
                            "description": "Name of the entity being updated"
                        },
                        "previous_tier": {
                            "type": "string",
                            "enum": ["background", "ambient", "active", "focal", "critical"],
                            "description": "Previous salience tier (if known)"
                        },
                        "new_tier": {
                            "type": "string",
                            "enum": ["background", "ambient", "active", "focal", "critical"],
                            "description": "New salience tier based on narrative context"
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Explanation for the salience change"
                        },
                        "confidence": {
                            "type": "number",
                            "minimum": 0.0,
                            "maximum": 1.0,
                            "description": "Confidence in this salience assessment (0.0-1.0)"
                        }
                    },
                    "required": ["entity_name", "new_tier", "reasoning", "confidence"]
                }
            }
        },
        "required": ["updates"]
    })
}

/// Convert structured output to internal types
impl PerceptionEntityExtractionOutput {
    pub fn to_contextual_entities(&self) -> Vec<super::perception_agent::ContextualEntity> {
        self.entities.iter().map(|e| super::perception_agent::ContextualEntity {
            name: e.name.clone(),
            entity_type: e.entity_type.clone(),
            relevance_score: e.relevance_score,
        }).collect()
    }
}

impl HierarchyAnalysisOutput {
    pub fn to_hierarchy_analysis_result(&self) -> super::perception_agent::HierarchyAnalysisResult {
        super::perception_agent::HierarchyAnalysisResult {
            hierarchy_insights: self.hierarchy_insights.iter().map(|h| super::perception_agent::HierarchyInsight {
                entity_name: h.entity_name.clone(),
                current_hierarchy: serde_json::Map::new(), // TODO: populate from insight
                hierarchy_depth: h.hierarchy_depth as u32,
                parent_entity: h.parent_entity.clone(),
                child_entities: h.child_entities.clone(),
            }).collect(),
            spatial_relationships: self.spatial_relationships.iter().map(|s| super::perception_agent::SpatialRelationship {
                entity_a: s.entity_a.clone(),
                entity_b: s.entity_b.clone(),
                relationship_type: s.relationship_type.clone(),
                confidence: 0.8, // Default confidence
            }).collect(),
            analysis_confidence: 0.85, // Default confidence
        }
    }
}

impl SalienceUpdateOutput {
    pub fn to_salience_updates(&self) -> Vec<super::perception_agent::SalienceUpdate> {
        self.updates.iter().map(|u| super::perception_agent::SalienceUpdate {
            entity_name: u.entity_name.clone(),
            previous_tier: u.previous_tier.clone(),
            new_tier: u.new_tier.clone(),
            reasoning: u.reasoning.clone(),
            confidence: u.confidence,
        }).collect()
    }
}