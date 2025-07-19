// Gemini-compatible schemas for hybrid query service
//
// This module provides Gemini-compatible versions of schemas used in hybrid_query_service.rs
// by removing the "additionalProperties" field that Gemini doesn't support.

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

/// Get Gemini-compatible entity context schema (without additionalProperties)
pub fn get_entity_context_schema_gemini() -> JsonValue {
    let schema = json!({
        "type": "object",
        "properties": {
            "attributes": {
                "type": "object",
                "description": "Key-value pairs of entity attributes extracted from events"
            },
            "dialogue_reveals": {
                "type": "object",
                "description": "Information revealed through dialogue, keyed by topic"
            },
            "skills": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Skills mentioned or demonstrated by the entity"
            },
            "equipment": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Equipment or items associated with the entity"
            },
            "profession": {
                "type": "string",
                "description": "The entity's profession or occupation"
            },
            "background": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Background information about the entity"
            },
            "actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Actions taken by the entity"
            }
        },
        "required": ["attributes", "dialogue_reveals", "skills", "equipment", "background", "actions"]
    });
    
    // Remove any additionalProperties that might have been added
    remove_additional_properties(schema)
}

/// Get Gemini-compatible item analysis schema (without additionalProperties)  
pub fn get_item_analysis_schema_gemini() -> JsonValue {
    let schema = json!({
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "item_id": {
                            "type": "string",
                            "description": "UUID of the item entity"
                        },
                        "item_name": {
                            "type": "string",
                            "description": "Name of the item"
                        },
                        "ownership_timeline": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "owner_entity_id": {
                                        "type": "string",
                                        "description": "UUID of the owner entity"
                                    },
                                    "owner_name": {
                                        "type": "string",
                                        "description": "Name of the owner"
                                    },
                                    "from_event": {
                                        "type": "string",
                                        "description": "Event ID when ownership started"
                                    },
                                    "to_event": {
                                        "type": ["string", "null"],
                                        "description": "Event ID when ownership ended (null if current)"
                                    }
                                }
                            },
                            "description": "Timeline of item ownership changes"
                        },
                        "usage_patterns": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "event_id": {
                                        "type": "string",
                                        "description": "Event ID where item was used"
                                    },
                                    "usage_type": {
                                        "type": "string",
                                        "description": "How the item was used (wielded, consumed, traded, etc.)"
                                    },
                                    "by_entity": {
                                        "type": "string",
                                        "description": "Entity ID who used the item"
                                    }
                                }
                            },
                            "description": "How the item has been used"
                        },
                        "lifecycle_stage": {
                            "type": "string",
                            "enum": ["created", "active", "lost", "destroyed", "transformed"],
                            "description": "Current stage of the item's lifecycle"
                        },
                        "location_history": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "location": {
                                        "type": "string",
                                        "description": "Location name or description"
                                    },
                                    "from_event": {
                                        "type": "string",
                                        "description": "Event ID when item arrived at location"
                                    }
                                }
                            },
                            "description": "History of where the item has been"
                        }
                    },
                    "required": ["item_id", "item_name", "ownership_timeline", "usage_patterns", "lifecycle_stage", "location_history"]
                },
                "description": "List of items found in the events"
            }
        },
        "required": ["items"]
    });
    
    // Remove any additionalProperties that might have been added
    remove_additional_properties(schema)
}