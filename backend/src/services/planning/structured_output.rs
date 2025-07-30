use serde::{Deserialize, Serialize};
use crate::errors::AppError;
use super::types::*;

/// Structured output schema for planning service
/// This ensures AI always generates valid JSON with proper types

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanGenerationOutput {
    pub goal: String,
    pub actions: Vec<PlannedActionOutput>,
    pub metadata: PlanMetadataOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedActionOutput {
    pub id: String,
    pub name: String, // Must be one of the valid action names
    pub parameters: serde_json::Value, // Dynamic parameters based on tool requirements
    pub preconditions: Option<PreconditionsOutput>,
    pub effects: Option<EffectsOutput>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanMetadataOutput {
    pub estimated_duration: Option<u64>,
    pub confidence: f32,
    pub alternative_considered: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreconditionsOutput {
    pub entity_exists: Option<Vec<EntityExistenceCheckOutput>>,
    pub entity_at_location: Option<Vec<EntityLocationCheckOutput>>,
    pub entity_has_component: Option<Vec<EntityComponentCheckOutput>>,
    pub inventory_has_space: Option<InventorySpaceCheckOutput>,
    pub relationship_exists: Option<Vec<RelationshipCheckOutput>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityExistenceCheckOutput {
    pub entity_id: Option<String>,
    pub entity_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityLocationCheckOutput {
    pub entity_id: String,
    pub location_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityComponentCheckOutput {
    pub entity_id: String,
    pub component_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventorySpaceCheckOutput {
    pub entity_id: String,
    pub required_slots: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipCheckOutput {
    pub source_entity_id: String,
    pub target_entity_id: String,
    pub min_trust: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectsOutput {
    pub entity_moved: Option<EntityMovedEffectOutput>,
    pub entity_created: Option<EntityCreatedEffectOutput>,
    pub component_updated: Option<Vec<ComponentUpdateEffectOutput>>,
    pub inventory_changed: Option<InventoryChangeEffectOutput>,
    pub relationship_changed: Option<RelationshipChangeEffectOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityMovedEffectOutput {
    pub entity_id: String,
    pub new_location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityCreatedEffectOutput {
    pub entity_name: String,
    pub entity_type: String,
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentUpdateEffectOutput {
    pub entity_id: String,
    pub component_type: String,
    pub operation: String, // "add", "update", "remove"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryChangeEffectOutput {
    pub entity_id: String,
    pub item_id: String,
    pub quantity_change: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipChangeEffectOutput {
    pub source_entity_id: String,
    pub target_entity_id: String,
    pub trust_change: Option<f32>,
    pub affection_change: Option<f32>,
}

/// Helper function to create the JSON schema for structured output with hardcoded tool names
pub fn get_plan_generation_schema() -> serde_json::Value {
    // Default tool names for backward compatibility
    let default_tools = vec![
        "find_entity".to_string(),
        "get_entity_details".to_string(), 
        "create_entity".to_string(),
        "update_entity".to_string(),
        "move_entity".to_string(),
        "get_contained_entities".to_string(),
        "get_spatial_context".to_string(),
        "add_item_to_inventory".to_string(),
        "remove_item_from_inventory".to_string(),
        "update_relationship".to_string(),
    ];
    get_plan_generation_schema_with_tools(&default_tools)
}

/// Helper function to create the JSON schema for structured output with dynamic tool names
pub fn get_plan_generation_schema_with_tools(tool_names: &[String]) -> serde_json::Value {
    // Get actual tool schemas from UnifiedToolRegistry
    use crate::services::agentic::unified_tool_registry::{UnifiedToolRegistry, AgentType};
    
    let all_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Tactical);
    let mut parameter_examples = serde_json::Map::new();
    
    // Build parameter examples from actual tool schemas
    for tool in all_tools.iter() {
        if tool_names.contains(&tool.name) {
            let input_schema = tool.input_schema.clone();
            if let Some(properties) = input_schema.get("properties") {
                if let Some(props_obj) = properties.as_object() {
                    let mut tool_params = serde_json::Map::new();
                    for (param_name, param_schema) in props_obj {
                        // Skip user_id as it's auto-injected by the system
                        if param_name != "user_id" {
                            tool_params.insert(param_name.clone(), param_schema.clone());
                        }
                    }
                    if !tool_params.is_empty() {
                        parameter_examples.insert(
                            tool.name.clone(), 
                            serde_json::Value::Object(tool_params)
                        );
                    }
                }
            }
        }
    }

    let parameter_description = if parameter_examples.is_empty() {
        "Tool-specific parameters. Refer to each tool's documentation for exact parameter names and types.".to_string()
    } else {
        format!(
            "Tool-specific parameters. Use the exact parameter names and types from each tool's schema. Tool parameters: {}",
            serde_json::to_string_pretty(&parameter_examples).unwrap_or_default()
        )
    };

    serde_json::json!({
        "type": "object",
        "properties": {
            "goal": {
                "type": "string",
                "description": "The goal being planned for"
            },
            "actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Unique identifier for this action (e.g., 'action_1', 'find_npc_1')"
                        },
                        "name": {
                            "type": "string",
                            "enum": tool_names,
                            "description": "The action to perform. Must be one of the exact values listed."
                        },
                        "parameters": {
                            "type": "object",
                            "description": parameter_description,
                            "additionalProperties": true
                        },
                        "dependencies": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "IDs of actions this depends on"
                        }
                    },
                    "required": ["id", "name", "parameters", "dependencies"]
                }
            },
            "metadata": {
                "type": "object",
                "properties": {
                    "estimated_duration": {
                        "type": "integer",
                        "description": "Estimated time in seconds"
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Confidence level from 0.0 to 1.0"
                    },
                    "alternative_considered": {
                        "type": "string",
                        "description": "Alternative approach that was considered"
                    }
                },
                "required": ["confidence"]
            }
        },
        "required": ["goal", "actions", "metadata"]
    })
}

/// Convert structured output to internal Plan type
impl PlanGenerationOutput {
    pub fn to_plan(&self) -> Result<Plan, AppError> {
        
        let mut actions = Vec::new();
        for action_output in &self.actions {
            // Action names are now dynamic strings - no need to convert to enum
            let action_name = action_output.name.clone();
            
            // Parameters are already JSON value - just clone
            let parameters = action_output.parameters.clone();
            
            // Convert preconditions
            let preconditions = if let Some(prec) = &action_output.preconditions {
                Preconditions {
                    entity_exists: prec.entity_exists.as_ref().map(|checks| 
                        checks.iter().map(|check| EntityExistenceCheck {
                            entity_id: check.entity_id.clone(),
                            entity_name: check.entity_name.clone(),
                        }).collect()
                    ),
                    entity_at_location: prec.entity_at_location.as_ref().map(|checks|
                        checks.iter().map(|check| EntityLocationCheck {
                            entity_id: check.entity_id.clone(),
                            location_id: check.location_id.clone(),
                        }).collect()
                    ),
                    entity_has_component: prec.entity_has_component.as_ref().map(|checks|
                        checks.iter().map(|check| EntityComponentCheck {
                            entity_id: check.entity_id.clone(),
                            component_type: check.component_type.clone(),
                        }).collect()
                    ),
                    inventory_has_space: prec.inventory_has_space.as_ref().map(|check|
                        InventorySpaceCheck {
                            entity_id: check.entity_id.clone(),
                            required_slots: check.required_slots,
                        }
                    ),
                    relationship_exists: prec.relationship_exists.as_ref().map(|checks|
                        checks.iter().map(|check| RelationshipCheck {
                            source_entity: check.source_entity_id.clone(),
                            target_entity: check.target_entity_id.clone(),
                            min_trust: check.min_trust,
                        }).collect()
                    ),
                }
            } else {
                Preconditions::default()
            };
            
            // Convert effects
            let effects = if let Some(eff) = &action_output.effects {
                Effects {
                    entity_moved: eff.entity_moved.as_ref().map(|moved| EntityMovedEffect {
                        entity_id: moved.entity_id.clone(),
                        new_location: moved.new_location.clone(),
                    }),
                    entity_created: eff.entity_created.as_ref().map(|created| EntityCreatedEffect {
                        entity_name: created.entity_name.clone(),
                        entity_type: created.entity_type.clone(),
                        parent_id: created.parent_id.clone(),
                    }),
                    component_updated: eff.component_updated.as_ref().map(|updates|
                        updates.iter().map(|update| ComponentUpdateEffect {
                            entity_id: update.entity_id.clone(),
                            component_type: update.component_type.clone(),
                            operation: match update.operation.as_str() {
                                "add" => ComponentOperation::Add,
                                "update" => ComponentOperation::Update,
                                "remove" => ComponentOperation::Remove,
                                _ => ComponentOperation::Update, // default
                            },
                        }).collect()
                    ),
                    inventory_changed: eff.inventory_changed.as_ref().map(|changed| InventoryChangeEffect {
                        entity_id: changed.entity_id.clone(),
                        item_id: changed.item_id.clone(),
                        quantity_change: changed.quantity_change,
                    }),
                    relationship_changed: eff.relationship_changed.as_ref().map(|changed| RelationshipChangeEffect {
                        source_entity: changed.source_entity_id.clone(),
                        target_entity: changed.target_entity_id.clone(),
                        trust_change: changed.trust_change,
                        affection_change: changed.affection_change,
                    }),
                }
            } else {
                Effects::default()
            };
            
            actions.push(PlannedAction {
                id: action_output.id.clone(),
                name: action_name,
                parameters,
                preconditions,
                effects,
                dependencies: action_output.dependencies.clone(),
            });
        }
        
        Ok(Plan {
            goal: self.goal.clone(),
            actions,
            metadata: PlanMetadata {
                estimated_duration: self.metadata.estimated_duration,
                confidence: self.metadata.confidence,
                alternative_considered: self.metadata.alternative_considered.clone(),
            },
        })
    }
}

/// Validation for structured output
impl PlanGenerationOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.goal.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Plan goal cannot be empty".to_string()
            ));
        }
        
        if self.actions.is_empty() {
            return Err(AppError::InvalidInput(
                "Plan must contain at least one action".to_string()
            ));
        }
        
        // For validation, we need to get the actual available tools
        // This is a limitation - validation should ideally be done with the same tool list
        // For now, we'll skip action name validation here since it's enforced by the schema
        
        for action in &self.actions {
            if action.id.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Action ID cannot be empty".to_string()
                ));
            }
        }
        
        // Validate dependencies
        let action_ids: Vec<&str> = self.actions.iter().map(|a| a.id.as_str()).collect();
        for action in &self.actions {
            for dep in &action.dependencies {
                if !action_ids.contains(&dep.as_str()) {
                    return Err(AppError::InvalidInput(
                        format!("Action {} has invalid dependency: {}", action.id, dep)
                    ));
                }
            }
        }
        
        Ok(())
    }
}