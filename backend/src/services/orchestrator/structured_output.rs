// backend/src/services/orchestrator/structured_output.rs
//
// Structured output schemas for Orchestrator Agent
// Ensures AI generates valid responses for each phase of the reasoning loop

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::errors::AppError;

/// Structured output schema for the Perceive phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerceptionPhaseOutput {
    pub entities_extracted: Vec<String>,
    pub locations_identified: Vec<String>,
    pub temporal_context: Option<String>,
    pub narrative_significance: f32, // 0.0-1.0
    pub world_state_delta: Option<serde_json::Value>,
}

/// Structured output schema for the Strategize phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyPhaseOutput {
    pub primary_goals: Vec<String>,
    pub narrative_threads: Vec<String>,
    pub world_state_implications: serde_json::Value,
    pub alternative_paths: Option<Vec<String>>,
}

/// Structured output schema for the Plan phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanPhaseOutput {
    pub action_steps: Vec<ActionStepOutput>,
    pub dependency_graph: Option<serde_json::Value>,
    pub tool_selections: HashMap<String, String>,
    pub cache_optimization_hints: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionStepOutput {
    pub action_name: String,
    pub description: String,
    pub tool_required: String,
    pub parameters: Option<serde_json::Value>,
    pub depends_on: Option<Vec<String>>,
}

/// Structured output schema for the Execute phase results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPhaseOutput {
    pub executed_actions: Vec<ExecutedActionOutput>,
    pub world_state_changes: serde_json::Value,
    pub cache_updates: Option<Vec<String>>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutedActionOutput {
    pub action_name: String,
    pub success: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// Structured output schema for the Reflect phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflectionPhaseOutput {
    pub goals_completed: Vec<String>,
    pub goals_remaining: Vec<String>,
    pub replan_needed: bool,
    pub cache_layers_to_update: Vec<String>,
    pub performance_assessment: String,
}

/// Helper function to create JSON schema for perception phase
pub fn get_perception_phase_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "entities_extracted": {
                "type": "array",
                "items": {"type": "string"},
                "description": "All entities mentioned in the interaction (characters, items, creatures)"
            },
            "locations_identified": {
                "type": "array",
                "items": {"type": "string"},
                "description": "All locations referenced in the interaction"
            },
            "temporal_context": {
                "type": "string",
                "description": "Temporal context (time of day, season, etc.)"
            },
            "narrative_significance": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Narrative significance score from 0.0 to 1.0"
            },
            "world_state_delta": {
                "type": "object",
                "properties": {
                    "analysis_type": {
                        "type": "string",
                        "enum": ["full", "delta"],
                        "description": "Type of analysis performed"
                    },
                    "entities_changed": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of entities that changed in this interaction"
                    },
                    "locations_changed": {
                        "type": "array", 
                        "items": {"type": "string"},
                        "description": "List of locations that changed in this interaction"
                    },
                    "state_modifications": {
                        "type": "object",
                        "properties": {
                            "entity_updates": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific entity state updates"
                            },
                            "location_updates": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific location state updates"  
                            },
                            "relationship_updates": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific relationship updates"
                            }
                        },
                        "description": "Specific modifications to world state"
                    }
                },
                "description": "Changes to world state (null for first message)"
            }
        },
        "required": ["entities_extracted", "locations_identified", "narrative_significance"]
    })
}

/// Helper function to create JSON schema for strategy phase
pub fn get_strategy_phase_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "primary_goals": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Primary enrichment goals for this interaction"
            },
            "narrative_threads": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Narrative threads to develop"
            },
            "world_state_implications": {
                "type": "object",
                "properties": {
                    "entity_implications": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Implications for entities in the world"
                    },
                    "location_implications": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Implications for locations in the world"
                    },
                    "narrative_implications": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Implications for overall narrative direction"
                    }
                },
                "description": "Implications for world state"
            },
            "alternative_paths": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Alternative narrative paths to consider"
            }
        },
        "required": ["primary_goals", "narrative_threads", "world_state_implications"]
    })
}

/// Helper function to create JSON schema for plan phase
pub fn get_plan_phase_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "action_steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "action_name": {
                            "type": "string",
                            "description": "Name of the action step"
                        },
                        "description": {
                            "type": "string",
                            "description": "Description of what this action does"
                        },
                        "tool_required": {
                            "type": "string",
                            "description": "Name of the tool required for this action"
                        },
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "tool_params": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "key": {"type": "string"},
                                            "value": {"type": "string"}
                                        }
                                    },
                                    "description": "Tool-specific parameters as key-value pairs"
                                }
                            },
                            "description": "Parameters for the tool execution"
                        },
                        "depends_on": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Names of actions this step depends on"
                        }
                    },
                    "required": ["action_name", "description", "tool_required"]
                },
                "description": "Concrete action steps to execute"
            },
            "dependency_graph": {
                "type": "object",
                "properties": {
                    "nodes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of action nodes"
                    },
                    "edges": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "from": {"type": "string"},
                                "to": {"type": "string"}
                            }
                        },
                        "description": "Dependencies between actions"
                    }
                },
                "description": "Dependency relationships between actions"
            },
            "tool_selections": {
                "type": "object",
                "properties": {
                    "mappings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": {"type": "string"},
                                "tool": {"type": "string"}
                            }
                        },
                        "description": "Action name to tool name mappings"
                    }
                },
                "description": "Mapping of action names to selected tools"
            },
            "cache_optimization_hints": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Hints for cache optimization"
            }
        },
        "required": ["action_steps", "tool_selections"]
    })
}

/// Helper function to create JSON schema for reflection phase
pub fn get_reflection_phase_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "goals_completed": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Goals that were successfully completed"
            },
            "goals_remaining": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Goals that still need to be addressed"
            },
            "replan_needed": {
                "type": "boolean",
                "description": "Whether replanning is needed for remaining goals"
            },
            "cache_layers_to_update": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["immediate_context", "enhanced_context", "full_world_state"]
                },
                "description": "Which cache layers should be updated"
            },
            "performance_assessment": {
                "type": "string",
                "description": "Assessment of overall phase performance"
            }
        },
        "required": ["goals_completed", "goals_remaining", "replan_needed", "cache_layers_to_update", "performance_assessment"]
    })
}

/// Convert structured output to internal types
impl PerceptionPhaseOutput {
    pub fn to_perception_result(&self) -> Result<crate::services::orchestrator::types::PerceptionResult, AppError> {
        use crate::services::orchestrator::types::PerceptionResult;
        
        Ok(PerceptionResult {
            entities_extracted: self.entities_extracted.clone(),
            locations_identified: self.locations_identified.clone(),
            temporal_context: self.temporal_context.clone(),
            narrative_significance: self.narrative_significance,
            world_state_delta: self.world_state_delta.clone(),
        })
    }
}

impl StrategyPhaseOutput {
    pub fn to_strategy_result(&self) -> Result<crate::services::orchestrator::types::StrategyResult, AppError> {
        use crate::services::orchestrator::types::StrategyResult;
        
        Ok(StrategyResult {
            primary_goals: self.primary_goals.clone(),
            narrative_threads: self.narrative_threads.clone(),
            world_state_implications: self.world_state_implications.clone(),
            alternative_paths: self.alternative_paths.clone(),
        })
    }
}

impl PlanPhaseOutput {
    pub fn to_plan_result(&self) -> Result<crate::services::orchestrator::types::PlanResult, AppError> {
        use crate::services::orchestrator::types::PlanResult;
        
        // Convert ActionStepOutput to JsonValue for compatibility
        let action_steps: Vec<serde_json::Value> = self.action_steps.iter()
            .map(|step| serde_json::json!({
                "action": step.action_name,
                "description": step.description,
                "tool": step.tool_required,
                "params": step.parameters,
                "depends_on": step.depends_on
            }))
            .collect();
        
        Ok(PlanResult {
            action_steps,
            dependency_graph: self.dependency_graph.clone(),
            tool_selections: self.tool_selections.clone(),
            cache_optimization_hints: self.cache_optimization_hints.clone(),
        })
    }
}

impl ExecutionPhaseOutput {
    pub fn to_execution_result(&self) -> Result<crate::services::orchestrator::types::ExecutionResult, AppError> {
        use crate::services::orchestrator::types::ExecutionResult;
        
        // Convert ExecutedActionOutput to JsonValue
        let executed_actions: Vec<serde_json::Value> = self.executed_actions.iter()
            .map(|action| serde_json::json!({
                "action": action.action_name,
                "success": action.success,
                "result": action.result,
                "error": action.error
            }))
            .collect();
        
        Ok(ExecutionResult {
            executed_actions,
            world_state_changes: self.world_state_changes.clone(),
            cache_updates: self.cache_updates.clone(),
            errors: self.errors.clone(),
        })
    }
}

impl ReflectionPhaseOutput {
    pub fn to_reflection_result(&self) -> Result<crate::services::orchestrator::types::ReflectionResult, AppError> {
        use crate::services::orchestrator::types::{ReflectionResult, PerformanceMetrics};
        use std::collections::HashMap;
        
        Ok(ReflectionResult {
            goals_completed: self.goals_completed.clone(),
            goals_remaining: self.goals_remaining.clone(),
            replan_needed: self.replan_needed,
            cache_layers_updated: self.cache_layers_to_update.clone(),
            performance_metrics: PerformanceMetrics {
                total_duration_ms: 0, // Would be calculated during execution
                phase_durations: HashMap::new(),
                cache_hits: 0,
                cache_misses: 0,
                tool_calls: 0,
            },
        })
    }
}

/// Validation for structured outputs
impl PerceptionPhaseOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.narrative_significance < 0.0 || self.narrative_significance > 1.0 {
            return Err(AppError::InvalidInput(
                "Narrative significance must be between 0.0 and 1.0".to_string()
            ));
        }
        Ok(())
    }
}

impl StrategyPhaseOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.primary_goals.is_empty() {
            return Err(AppError::InvalidInput(
                "At least one primary goal is required".to_string()
            ));
        }
        if self.narrative_threads.is_empty() {
            return Err(AppError::InvalidInput(
                "At least one narrative thread is required".to_string()
            ));
        }
        Ok(())
    }
}

impl PlanPhaseOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.action_steps.is_empty() {
            return Err(AppError::InvalidInput(
                "At least one action step is required".to_string()
            ));
        }
        
        for step in &self.action_steps {
            if step.action_name.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Action step name cannot be empty".to_string()
                ));
            }
            if step.tool_required.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Tool required cannot be empty".to_string()
                ));
            }
        }
        
        Ok(())
    }
}

impl ReflectionPhaseOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.performance_assessment.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Performance assessment cannot be empty".to_string()
            ));
        }
        
        // Validate cache layer names
        let valid_layers = ["immediate_context", "enhanced_context", "full_world_state"];
        for layer in &self.cache_layers_to_update {
            if !valid_layers.contains(&layer.as_str()) {
                return Err(AppError::InvalidInput(
                    format!("Invalid cache layer: {}", layer)
                ));
            }
        }
        
        Ok(())
    }
}