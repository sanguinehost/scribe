// Hierarchy Management Tools for Agents
//
// These tools allow agents to manipulate spatial hierarchies in JSON format,
// enabling dynamic promotion and restructuring of entity relationships.

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, debug, instrument};

use crate::{
    services::EcsEntityManager,
    services::agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    services::agentic::unified_tool_registry::{
        SelfRegisteringTool, ToolCategory, ToolCapability, ToolSecurityPolicy, AgentType,
        ToolExample, DataAccessPolicy, AuditLevel, ResourceRequirements, ExecutionTime, ErrorCode
    },
    errors::AppError,
    auth::session_dek::SessionDek,
};

// Note: PromoteEntityHierarchyTool has been removed as it's superseded by 
// the AI-driven SuggestHierarchyPromotionTool in ai_powered_tools.rs

/// Information about a level in the hierarchy
#[derive(Debug, Serialize, Clone)]
pub struct HierarchyLevel {
    pub entity_id: String,
    pub name: String,
    pub scale: Option<String>,
    pub level: u32,
    pub depth_from_root: u32,
    pub relationship: Option<String>,
}

/// Tool for getting the complete hierarchy path of an entity
#[derive(Clone)]
pub struct GetEntityHierarchyTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl GetEntityHierarchyTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input for getting entity hierarchy
#[derive(Debug, Deserialize)]
pub struct GetHierarchyInput {
    /// User ID performing the operation
    pub user_id: String,
    /// ID of the entity to get hierarchy for
    pub entity_id: String,
}

/// Output with hierarchy information
#[derive(Debug, Serialize)]
pub struct GetHierarchyOutput {
    /// The entity that was queried
    pub entity_id: String,
    /// Complete hierarchy path from root to entity
    pub hierarchy_path: Vec<HierarchyLevel>,
    /// Total depth of the hierarchy
    pub total_depth: u32,
    /// Root entity information
    pub root_entity: HierarchyLevel,
}

#[async_trait]
impl ScribeTool for GetEntityHierarchyTool {
    fn name(&self) -> &'static str {
        "get_entity_hierarchy"
    }

    fn description(&self) -> &'static str {
        "Gets the complete hierarchy path for an entity, from root to the entity itself. \
         Useful for understanding spatial containment and planning movement between scales."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user performing the operation"
                },
                "entity_id": {
                    "type": "string",
                    "description": "UUID of the entity to get hierarchy information for"
                }
            },
            "required": ["user_id", "entity_id"]
        })
    }

    #[instrument(skip(self, params, _session_dek), fields(tool = self.name()))]
    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        debug!("Executing get_entity_hierarchy with input: {}", params);
        
        // Parse input
        let input_params: GetHierarchyInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input parameters: {}", e)))?;

        // Parse user ID
        let user_id = Uuid::parse_str(&input_params.user_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid user_id UUID: {}", input_params.user_id)))?;

        // Parse entity ID
        let entity_id = Uuid::parse_str(&input_params.entity_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid entity_id UUID: {}", input_params.entity_id)))?;

        // Get hierarchy path
        let hierarchy_path = self.entity_manager.get_entity_hierarchy_path(user_id, entity_id).await
            .map_err(|e| ToolError::AppError(e))?;
        
        if hierarchy_path.is_empty() {
            return Err(ToolError::ExecutionFailed(format!("Entity not found: {}", input_params.entity_id)));
        }

        let hierarchy_levels: Vec<HierarchyLevel> = hierarchy_path.iter().map(|info| {
            HierarchyLevel {
                entity_id: info.entity_id.to_string(),
                name: info.name.clone(),
                scale: info.scale.as_ref().map(|s| format!("{:?}", s)),
                level: info.hierarchical_level,
                depth_from_root: info.depth_from_root,
                relationship: info.relationship.clone(),
            }
        }).collect();

        let root_entity = hierarchy_levels.first().unwrap().clone();
        let total_depth = hierarchy_path.len() as u32;

        let output = GetHierarchyOutput {
            entity_id: input_params.entity_id,
            hierarchy_path: hierarchy_levels,
            total_depth,
            root_entity,
        };

        info!("Retrieved hierarchy for entity {}: {} levels", entity_id, total_depth);

        Ok(serde_json::to_value(output)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to serialize output: {}", e)))?)
    }
}

#[async_trait]
impl SelfRegisteringTool for GetEntityHierarchyTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Discovery
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "retrieve".to_string(),
                target: "entity hierarchy".to_string(),
                context: Some("direct query".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "DEPRECATED: Use AI-driven AnalyzeHierarchyRequestTool instead. \
         This is a legacy tool that directly queries hierarchy without AI interpretation.".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Always prefer the AI-driven AnalyzeHierarchyRequestTool which can interpret \
         natural language queries and provide intelligent reasoning about hierarchies.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Legacy hierarchy query".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "entity_id": "456e7890-e12b-34c5-a789-012345678901"
                }),
                expected_output: "Returns complete hierarchy path from root to entity (legacy direct query)".to_string(),
            },
        ]
    }
    
    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
                AgentType::Perception,
            ],
            required_capabilities: vec![],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false, // Read-only query
                allowed_scopes: vec!["hierarchy".to_string(), "entities".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 30,
            execution_time: ExecutionTime::Fast, // Direct DB query
            external_calls: false,
            compute_intensive: false,
        }
    }
    
    fn dependencies(&self) -> Vec<String> {
        vec!["ecs_entity_manager".to_string()]
    }
    
    fn tags(&self) -> Vec<String> {
        vec![
            "hierarchy".to_string(),
            "query".to_string(),
            "legacy".to_string(),
            "deprecated".to_string(),
            "direct-query".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "entity_id": {
                    "type": "string",
                    "description": "UUID of the queried entity"
                },
                "hierarchy_path": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "entity_id": {"type": "string"},
                            "name": {"type": "string"},
                            "scale": {"type": "string"},
                            "level": {"type": "integer"},
                            "depth_from_root": {"type": "integer"},
                            "relationship": {"type": "string"}
                        }
                    },
                    "description": "Complete hierarchy path from root to entity"
                },
                "total_depth": {
                    "type": "integer",
                    "description": "Total depth of the hierarchy"
                },
                "root_entity": {
                    "type": "object",
                    "description": "Information about the root entity in the hierarchy"
                }
            },
            "required": ["entity_id", "hierarchy_path", "total_depth", "root_entity"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "ENTITY_NOT_FOUND".to_string(),
                description: "The specified entity was not found".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "HIERARCHY_QUERY_FAILED".to_string(),
                description: "Failed to retrieve hierarchy information".to_string(),
                retry_able: true,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "1.0.0-legacy"
    }
}

/// Register hierarchy tools with the unified registry
/// Note: Only registering GetEntityHierarchyTool as it's still needed by AI tools
pub fn register_hierarchy_tools(entity_manager: Arc<EcsEntityManager>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    // NOTE: PromoteEntityHierarchyTool is NOT registered as it's superseded by 
    // the AI-driven SuggestHierarchyPromotionTool in ai_powered_tools.rs
    
    // Register GetEntityHierarchyTool (still needed by AI tools as data layer)
    let get_hierarchy_tool = Arc::new(GetEntityHierarchyTool::new(entity_manager.clone())) 
        as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register_if_not_exists(get_hierarchy_tool)?;
    
    tracing::info!("Registered 1 hierarchy tool (GetEntityHierarchyTool) - still needed by AI tools");
    Ok(())
}