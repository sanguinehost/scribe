use serde::{Deserialize, Serialize};
use crate::errors::AppError;

/// Structured output schema for Tactical Agent planning phase
/// This ensures AI generates valid action plans with proper tool usage

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticalPlanningOutput {
    pub goal: String,
    pub actions: Vec<TacticalActionOutput>,
    pub metadata: TacticalMetadataOutput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticalActionOutput {
    pub id: String,
    pub name: String, // Must be one of the available tool names from UnifiedToolRegistry
    pub parameters: serde_json::Value, // Dynamic parameters based on tool requirements
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticalMetadataOutput {
    pub confidence: f32,
    pub estimated_duration: Option<u64>,
    pub phase_3_atomic: bool, // Indicates if this plan contains atomic operations
}

/// Helper function to create the JSON schema for tactical planning with dynamic tool names
pub fn get_tactical_planning_schema(tool_names: &[String]) -> serde_json::Value {
    // Get tool schemas from UnifiedToolRegistry for proper parameter definitions
    use crate::services::agentic::unified_tool_registry::{UnifiedToolRegistry, AgentType};
    
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Tactical);
    let mut tool_parameters_schemas = serde_json::Map::new();
    
    // Build parameter schemas for each tool based on their input_schema
    for tool in tools.iter() {
        if tool_names.contains(&tool.name) {
            let input_schema = tool.input_schema.clone();
            if let Some(properties) = input_schema.get("properties") {
                tool_parameters_schemas.insert(tool.name.clone(), properties.clone());
            }
        }
    }
    
    serde_json::json!({
        "type": "object",
        "properties": {
            "goal": {
                "type": "string",
                "description": "The tactical goal being planned for"
            },
            "actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {
                            "type": "string",
                            "description": "Unique identifier for this action (e.g., 'action_1', 'tactical_1')"
                        },
                        "name": {
                            "type": "string",
                            "enum": tool_names,
                            "description": "The tool to execute. Must be one of the exact values listed."
                        },
                        "parameters": {
                            "type": "object",
                            "description": "Tool-specific parameters. Each tool expects different parameters as defined in the tool descriptions. For example, create_entity expects 'creation_request' and 'context', find_entity expects 'search_request', 'context', and 'limit', etc.",
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
                    "confidence": {
                        "type": "number",
                        "minimum": 0.0,
                        "maximum": 1.0,
                        "description": "Confidence level from 0.0 to 1.0"
                    },
                    "estimated_duration": {
                        "type": "integer",
                        "description": "Estimated time in seconds"
                    },
                    "phase_3_atomic": {
                        "type": "boolean",
                        "description": "Whether this plan contains atomic operations that must be executed without interruption"
                    }
                },
                "required": ["confidence", "phase_3_atomic"]
            }
        },
        "required": ["goal", "actions", "metadata"]
    })
}

/// Convert structured output to internal TacticalPlan type
impl TacticalPlanningOutput {
    pub fn to_tactical_plan(&self) -> Result<crate::services::agentic::types::TacticalPlan, AppError> {
        use crate::services::agentic::types::{TacticalPlan, TacticalAction};
        
        let mut actions = Vec::new();
        for action_output in &self.actions {
            actions.push(TacticalAction {
                id: action_output.id.clone(),
                name: action_output.name.clone(),
                parameters: action_output.parameters.clone(),
                dependencies: action_output.dependencies.clone(),
            });
        }
        
        Ok(TacticalPlan {
            goal: self.goal.clone(),
            actions,
            confidence: self.metadata.confidence,
            estimated_duration: self.metadata.estimated_duration,
            phase_3_atomic: self.metadata.phase_3_atomic,
        })
    }
}

/// Validation for structured output
impl TacticalPlanningOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.goal.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "Tactical goal cannot be empty".to_string()
            ));
        }
        
        if self.actions.is_empty() {
            return Err(AppError::InvalidInput(
                "Tactical plan must contain at least one action".to_string()
            ));
        }
        
        // Validate each action
        for action in &self.actions {
            if action.id.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Action ID cannot be empty".to_string()
                ));
            }
            
            if action.name.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Action name cannot be empty".to_string()
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
        
        // Validate metadata
        if self.metadata.confidence < 0.0 || self.metadata.confidence > 1.0 {
            return Err(AppError::InvalidInput(
                "Confidence must be between 0.0 and 1.0".to_string()
            ));
        }
        
        Ok(())
    }
}