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
    models::ecs::{SpatialScale, PositionType, HierarchicalCoordinates},
    services::agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
};

/// Tool for promoting an entity to have a new parent, expanding the hierarchy
/// This handles the case where scope needs to expand (e.g., planet → solar system)
#[derive(Clone)]
pub struct PromoteEntityHierarchyTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl PromoteEntityHierarchyTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input parameters for hierarchy promotion (JSON format for agents)
#[derive(Debug, Deserialize)]
pub struct PromoteHierarchyInput {
    /// User ID performing the operation
    pub user_id: String,
    /// ID of the entity to promote (give a new parent to)
    pub entity_id: String,
    /// Name for the new parent entity
    pub new_parent_name: String,
    /// Scale of the new parent (Cosmic, Planetary, Intimate)
    pub new_parent_scale: String,
    /// Position information for the new parent
    pub new_parent_position: NewParentPosition,
    /// Relationship type between entity and new parent
    pub relationship_type: String,
}

/// Position configuration for the new parent entity
#[derive(Debug, Deserialize)]
pub struct NewParentPosition {
    /// Position type: "absolute" or "relative"
    pub position_type: String,
    /// Coordinates for the new parent
    pub coordinates: PositionCoordinates,
    /// If relative, the entity it's relative to
    pub relative_to_entity: Option<String>,
}

/// Coordinate specification
#[derive(Debug, Deserialize)]
pub struct PositionCoordinates {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    /// Optional metadata for the position
    pub metadata: Option<serde_json::Map<String, JsonValue>>,
}

/// Output from hierarchy promotion
#[derive(Debug, Serialize)]
pub struct PromoteHierarchyOutput {
    /// ID of the newly created parent entity
    pub new_parent_id: String,
    /// Name of the new parent
    pub new_parent_name: String,
    /// Original entity ID that was promoted
    pub promoted_entity_id: String,
    /// Success message
    pub message: String,
    /// New hierarchy structure
    pub hierarchy_path: Vec<HierarchyLevel>,
}

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

#[async_trait]
impl ScribeTool for PromoteEntityHierarchyTool {
    fn name(&self) -> &'static str {
        "promote_entity_hierarchy"
    }

    fn description(&self) -> &'static str {
        "Promotes an entity to have a new parent, expanding the spatial hierarchy. \
         Use this when scope needs to expand (e.g., moving from planet level to galaxy level). \
         Creates a new parent entity and restructures the hierarchy accordingly."
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
                    "description": "UUID of the entity to promote (give a new parent to)"
                },
                "new_parent_name": {
                    "type": "string",
                    "description": "Name for the new parent entity (e.g., 'Tatooine System', 'Milky Way Galaxy')"
                },
                "new_parent_scale": {
                    "type": "string",
                    "enum": ["Cosmic", "Planetary", "Intimate"],
                    "description": "Spatial scale of the new parent entity"
                },
                "new_parent_position": {
                    "type": "object",
                    "properties": {
                        "position_type": {
                            "type": "string",
                            "enum": ["absolute", "relative"],
                            "description": "Whether the new parent has absolute or relative positioning"
                        },
                        "coordinates": {
                            "type": "object",
                            "properties": {
                                "x": {"type": "number"},
                                "y": {"type": "number"},
                                "z": {"type": "number"},
                                "metadata": {
                                    "type": "object",
                                    "description": "Optional metadata for the position"
                                }
                            },
                            "required": ["x", "y", "z"]
                        },
                        "relative_to_entity": {
                            "type": "string",
                            "description": "UUID of entity this is relative to (only if position_type is 'relative')"
                        }
                    },
                    "required": ["position_type", "coordinates"]
                },
                "relationship_type": {
                    "type": "string",
                    "description": "Type of spatial relationship (e.g., 'orbits', 'contained_within', 'part_of')"
                }
            },
            "required": ["user_id", "entity_id", "new_parent_name", "new_parent_scale", "new_parent_position", "relationship_type"]
        })
    }

    #[instrument(skip(self, params), fields(tool = self.name()))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing promote_entity_hierarchy with input: {}", params);
        
        // Parse input
        let input_params: PromoteHierarchyInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input parameters: {}", e)))?;

        // Parse user ID
        let user_id = Uuid::parse_str(&input_params.user_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid user_id UUID: {}", input_params.user_id)))?;

        // Parse entity ID
        let entity_id = Uuid::parse_str(&input_params.entity_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid entity_id UUID: {}", input_params.entity_id)))?;

        // Parse spatial scale
        let spatial_scale = match input_params.new_parent_scale.as_str() {
            "Cosmic" => SpatialScale::Cosmic,
            "Planetary" => SpatialScale::Planetary,
            "Intimate" => SpatialScale::Intimate,
            _ => return Err(ToolError::InvalidParams(format!("Invalid spatial scale: {}", input_params.new_parent_scale))),
        };

        // Parse position type
        let position_type = match input_params.new_parent_position.position_type.as_str() {
            "absolute" => {
                let coordinates = HierarchicalCoordinates {
                    x: input_params.new_parent_position.coordinates.x,
                    y: input_params.new_parent_position.coordinates.y,
                    z: input_params.new_parent_position.coordinates.z,
                    scale: spatial_scale,
                    metadata: input_params.new_parent_position.coordinates.metadata.unwrap_or_default(),
                };
                PositionType::Absolute { coordinates }
            }
            "relative" => {
                let relative_to_entity = input_params.new_parent_position.relative_to_entity
                    .ok_or_else(|| ToolError::InvalidParams("relative_to_entity required for relative positioning".to_string()))?;
                
                let relative_to_uuid = Uuid::parse_str(&relative_to_entity)
                    .map_err(|_| ToolError::InvalidParams(format!("Invalid relative_to_entity UUID: {}", relative_to_entity)))?;
                
                let coordinates = HierarchicalCoordinates {
                    x: input_params.new_parent_position.coordinates.x,
                    y: input_params.new_parent_position.coordinates.y,
                    z: input_params.new_parent_position.coordinates.z,
                    scale: spatial_scale,
                    metadata: input_params.new_parent_position.coordinates.metadata.unwrap_or_default(),
                };
                
                PositionType::Relative {
                    relative_to_entity: relative_to_uuid,
                    coordinates,
                }
            }
            _ => return Err(ToolError::InvalidParams(format!("Invalid position_type: {}", input_params.new_parent_position.position_type))),
        };

        // Re-parse spatial scale for the function call since we moved it into the position_type
        let spatial_scale_for_call = match input_params.new_parent_scale.as_str() {
            "Cosmic" => SpatialScale::Cosmic,
            "Planetary" => SpatialScale::Planetary,
            "Intimate" => SpatialScale::Intimate,
            _ => return Err(ToolError::InvalidParams(format!("Invalid spatial scale: {}", input_params.new_parent_scale))),
        };

        // Execute hierarchy promotion
        let new_parent_id = self.entity_manager.promote_entity_hierarchy(
            user_id,
            entity_id,
            input_params.new_parent_name.clone(),
            spatial_scale_for_call,
            position_type,
            input_params.relationship_type.clone(),
        ).await
        .map_err(|e| ToolError::AppError(e))?;

        // Get the updated hierarchy path
        let hierarchy_path = self.entity_manager.get_entity_hierarchy_path(user_id, entity_id).await
            .map_err(|e| ToolError::AppError(e))?;
        
        let hierarchy_levels: Vec<HierarchyLevel> = hierarchy_path.into_iter().map(|info| {
            HierarchyLevel {
                entity_id: info.entity_id.to_string(),
                name: info.name,
                scale: info.scale.map(|s| format!("{:?}", s)),
                level: info.hierarchical_level,
                depth_from_root: info.depth_from_root,
                relationship: info.relationship,
            }
        }).collect();

        let output = PromoteHierarchyOutput {
            new_parent_id: new_parent_id.to_string(),
            new_parent_name: input_params.new_parent_name.clone(),
            promoted_entity_id: input_params.entity_id.clone(),
            message: format!("Successfully promoted entity '{}' with new parent '{}'", 
                           input_params.entity_id, input_params.new_parent_name),
            hierarchy_path: hierarchy_levels,
        };

        info!("Successfully promoted entity {} hierarchy. New parent: {}", entity_id, new_parent_id);

        Ok(serde_json::to_value(output)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to serialize output: {}", e)))?)
    }
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

    #[instrument(skip(self, params), fields(tool = self.name()))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
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