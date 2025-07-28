// Structured output schemas for AI-powered tools
//
// This module provides JSON schemas for structured output from AI models,
// ensuring reliable parsing of AI responses for various tool operations.

use serde_json::{json, Value as JsonValue};

/// Remove additionalProperties from a schema (for Gemini compatibility)
fn remove_additional_properties(mut schema: JsonValue) -> JsonValue {
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

/// Get JSON schema for salience analysis output (Gemini-compatible version without additionalProperties)
pub fn get_salience_analysis_schema_gemini() -> JsonValue {
    let schema = get_salience_analysis_schema();
    remove_additional_properties(schema)
}

/// Get JSON schema for salience analysis output
pub fn get_salience_analysis_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "analysis": {
                "type": "string",
                "description": "Detailed analysis of the entity's narrative role"
            },
            "recommended_tier": {
                "type": "string",
                "enum": ["Core", "Secondary", "Flavor"],
                "description": "Recommended salience tier for the entity"
            },
            "reasoning": {
                "type": "string",
                "description": "Explanation for the recommended tier"
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Confidence level in the recommendation"
            },
            "scale_context": {
                "type": "string",
                "enum": ["Cosmic", "Planetary", "Intimate"],
                "description": "The scale at which this entity operates"
            },
            "interaction_indicators": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Evidence of entity interactions from the narrative"
            },
            "persistence_reasoning": {
                "type": "string",
                "description": "Why this entity should or shouldn't persist"
            },
            "change_from_current": {
                "type": "string",
                "enum": ["upgrade", "downgrade", "maintain", "initial_assignment"],
                "description": "Type of change from current state"
            }
        },
        "required": [
            "analysis",
            "recommended_tier",
            "reasoning",
            "confidence",
            "scale_context",
            "interaction_indicators",
            "persistence_reasoning",
            "change_from_current"
        ],
        "additionalProperties": false
    })
}

/// Get JSON schema for hierarchy interpretation output (Gemini-compatible version without additionalProperties)
pub fn get_hierarchy_interpretation_schema_gemini() -> JsonValue {
    let schema = get_hierarchy_interpretation_schema();
    remove_additional_properties(schema)
}

/// Get JSON schema for hierarchy interpretation output
pub fn get_hierarchy_interpretation_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "interpretation": {
                "type": "string",
                "description": "Clear restatement of what the user is asking for"
            },
            "query_type": {
                "type": "string",
                "enum": ["hierarchy_path", "containment_query", "command_structure", "spatial_relationships"],
                "description": "Type of hierarchy query"
            },
            "target_entities": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "Names of entities involved in the query"
            },
            "scope": {
                "type": "string",
                "enum": ["Cosmic", "Planetary", "Intimate"],
                "description": "Scale scope of the query"
            },
            "reasoning": {
                "type": "string",
                "description": "Explanation of the interpretation"
            },
            "suggested_query": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["get_entity_hierarchy", "custom_query"],
                        "description": "Suggested action to execute"
                    },
                    "parameters": {
                        "type": "object",
                        "description": "Parameters for the suggested action"
                    }
                },
                "required": ["action", "parameters"],
                "additionalProperties": false
            }
        },
        "required": [
            "interpretation",
            "query_type",
            "target_entities",
            "scope",
            "reasoning",
            "suggested_query"
        ],
        "additionalProperties": false
    })
}

/// Get JSON schema for promotion analysis output (Gemini-compatible version without additionalProperties)
pub fn get_promotion_analysis_schema_gemini() -> JsonValue {
    let schema = get_promotion_analysis_schema();
    remove_additional_properties(schema)
}

/// Get JSON schema for component suggestion output (Gemini-compatible version without additionalProperties)
pub fn get_component_suggestion_schema_gemini() -> JsonValue {
    let schema = get_component_suggestion_schema();
    remove_additional_properties(schema)
}

/// Get JSON schema for semantic match output (Gemini-compatible version without additionalProperties)
pub fn get_semantic_match_schema_gemini() -> JsonValue {
    let schema = get_semantic_match_schema();
    remove_additional_properties(schema)
}

/// Get JSON schema for promotion analysis output
pub fn get_promotion_analysis_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "analysis": {
                "type": "string",
                "description": "Summary of narrative patterns observed"
            },
            "promotion_suggestions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_name": {
                            "type": "string",
                            "description": "Name of entity to promote"
                        },
                        "current_perceived_tier": {
                            "type": "string",
                            "enum": ["Core", "Secondary", "Flavor"],
                            "description": "Current perceived salience tier"
                        },
                        "suggested_new_tier": {
                            "type": "string",
                            "enum": ["Core", "Secondary"],
                            "description": "Suggested new salience tier"
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Why this promotion makes sense"
                        },
                        "evidence": {
                            "type": "array",
                            "items": {
                                "type": "string"
                            },
                            "description": "Quotes from narrative supporting promotion"
                        },
                        "suggested_hierarchy": {
                            "type": "object",
                            "properties": {
                                "new_parent_name": {
                                    "type": "string",
                                    "description": "Suggested parent entity name"
                                },
                                "scale": {
                                    "type": "string",
                                    "enum": ["Cosmic", "Planetary", "Intimate"],
                                    "description": "Scale of the hierarchy relationship"
                                },
                                "relationship_type": {
                                    "type": "string",
                                    "enum": ["command_structure", "spatial_containment", "organizational"],
                                    "description": "Type of hierarchy relationship"
                                }
                            },
                            "required": ["new_parent_name", "scale", "relationship_type"],
                            "additionalProperties": false
                        }
                    },
                    "required": [
                        "entity_name",
                        "current_perceived_tier",
                        "suggested_new_tier",
                        "reasoning",
                        "evidence",
                        "suggested_hierarchy"
                    ],
                    "additionalProperties": false
                },
                "description": "List of entities to promote with details"
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Overall confidence in the promotion suggestions"
            }
        },
        "required": [
            "analysis",
            "promotion_suggestions",
            "confidence"
        ],
        "additionalProperties": false
    })
}

/// Get JSON schema for component suggestion output
pub fn get_component_suggestion_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "suggested_components": {
                "type": "array",
                "items": {
                    "type": "string"
                },
                "description": "List of ECS components suggested for the entity"
            },
            "reasoning": {
                "type": "string",
                "description": "Explanation of why these components fit the narrative context"
            },
            "contextual_insights": {
                "type": "string",
                "description": "What the narrative reveals about this entity"
            }
        },
        "required": [
            "suggested_components",
            "reasoning",
            "contextual_insights"
        ],
        "additionalProperties": false
    })
}

/// Get JSON schema for semantic match output
pub fn get_semantic_match_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "match_found": {
                "type": "boolean",
                "description": "Whether a semantic match was found"
            },
            "matched_index": {
                "type": ["integer", "null"],
                "description": "0-based index of matched entity or null if no match"
            },
            "matched_name": {
                "type": ["string", "null"],
                "description": "Name of matched entity or null if no match"
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Confidence level in the match (0.0-1.0)"
            },
            "reasoning": {
                "type": "string",
                "description": "Explanation of the match or why no match was found"
            }
        },
        "required": [
            "match_found",
            "matched_index",
            "matched_name",
            "confidence",
            "reasoning"
        ],
        "additionalProperties": false
    })
}