//! World Interaction Tools for the Planning Cortex
//!
//! These tools provide atomic operations for finding, inspecting, creating, and modifying
//! entities in the world simulation. They serve as the tactical toolkit for the Planning Cortex
//! to execute world changes based on narrative intelligence.

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, debug, instrument, error};

use crate::{
    services::{EcsEntityManager, ComponentQuery, EntityQueryResult},
    models::ecs::{SpatialScale, PositionType},
    services::agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    errors::AppError,
};

/// Tool for finding entities by various criteria
#[derive(Clone)]
pub struct FindEntityTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl FindEntityTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input parameters for finding entities
#[derive(Debug, Deserialize)]
pub struct FindEntityInput {
    /// User ID performing the operation
    pub user_id: String,
    /// Search criteria
    pub criteria: EntitySearchCriteria,
    /// Maximum number of results to return (default: 10)
    pub limit: Option<usize>,
}

/// Search criteria for finding entities
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum EntitySearchCriteria {
    /// Search by name (partial match)
    ByName { name: String },
    /// Search by spatial scale
    ByScale { scale: String },
    /// Search by parent entity
    ByParent { parent_id: String },
    /// Search by component presence
    ByComponent { component_type: String },
    /// Advanced query with multiple criteria
    Advanced { queries: Vec<ComponentQueryInput> },
}

/// Input format for component queries
#[derive(Debug, Deserialize)]
pub struct ComponentQueryInput {
    pub component_type: String,
    pub has_component: Option<bool>,
    pub field_path: Option<String>,
    pub field_value: Option<JsonValue>,
}

/// Output from entity search
#[derive(Debug, Serialize)]
pub struct FindEntityOutput {
    pub entities: Vec<EntitySummary>,
    pub total_found: usize,
    pub search_criteria: String,
}

/// Summary information about an entity
#[derive(Debug, Serialize)]
pub struct EntitySummary {
    pub entity_id: String,
    pub name: String,
    pub scale: Option<String>,
    pub position: Option<PositionSummary>,
    pub parent_id: Option<String>,
    pub component_types: Vec<String>,
}

/// Position summary for entities
#[derive(Debug, Serialize)]
pub struct PositionSummary {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub scale: Option<String>,
}

#[async_trait]
impl ScribeTool for FindEntityTool {
    fn name(&self) -> &'static str {
        "find_entity"
    }

    fn description(&self) -> &'static str {
        "Find entities in the world by various criteria such as name, scale, parent, or component type. \
         Returns a list of matching entities with summary information."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the search"
                },
                "criteria": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByName" },
                                "name": { "type": "string", "description": "Name to search for (partial match)" }
                            },
                            "required": ["type", "name"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByScale" },
                                "scale": { "type": "string", "enum": ["Cosmic", "Planetary", "Intimate"] }
                            },
                            "required": ["type", "scale"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByParent" },
                                "parent_id": { "type": "string", "description": "UUID of parent entity" }
                            },
                            "required": ["type", "parent_id"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByComponent" },
                                "component_type": { "type": "string", "description": "Component type to search for" }
                            },
                            "required": ["type", "component_type"]
                        }
                    ]
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Maximum number of results to return"
                }
            },
            "required": ["user_id", "criteria"]
        })
    }

    #[instrument(skip(self, params), fields(tool = "find_entity"))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        let input: FindEntityInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;

        let limit = input.limit.unwrap_or(10).min(100);

        info!("Finding entities for user {} with criteria: {:?}", user_id, input.criteria);

        let search_criteria_desc = match &input.criteria {
            EntitySearchCriteria::ByName { name } => format!("ByName({})", name),
            EntitySearchCriteria::ByScale { scale } => format!("ByScale({})", scale),
            EntitySearchCriteria::ByParent { parent_id } => format!("ByParent({})", parent_id),
            EntitySearchCriteria::ByComponent { component_type } => format!("ByComponent({})", component_type),
            EntitySearchCriteria::Advanced { queries: _ } => "Advanced".to_string(),
        };

        let entities = match input.criteria {
            EntitySearchCriteria::ByName { name } => {
                self.find_by_name(user_id, &name, limit).await?
            },
            EntitySearchCriteria::ByScale { scale } => {
                self.find_by_scale(user_id, &scale, limit).await?
            },
            EntitySearchCriteria::ByParent { parent_id } => {
                let parent_uuid = Uuid::parse_str(&parent_id)
                    .map_err(|e| ToolError::InvalidParams(format!("Invalid parent_id: {}", e)))?;
                self.find_by_parent(user_id, parent_uuid, limit).await?
            },
            EntitySearchCriteria::ByComponent { component_type } => {
                self.find_by_component(user_id, &component_type, limit).await?
            },
            EntitySearchCriteria::Advanced { queries } => {
                self.find_by_advanced_query(user_id, queries, limit).await?
            },
        };

        let output = FindEntityOutput {
            total_found: entities.len(),
            search_criteria: search_criteria_desc,
            entities,
        };

        info!("Found {} entities", output.total_found);
        Ok(serde_json::to_value(output)?)
    }
}

impl FindEntityTool {
    async fn find_by_name(&self, user_id: Uuid, name: &str, limit: usize) -> Result<Vec<EntitySummary>, ToolError> {
        let queries = vec![ComponentQuery::ComponentDataMatches(
            "Name".to_string(),
            "name".to_string(),
            name.to_string(),
        )];

        let results = self.entity_manager.query_entities(user_id, queries, Some(limit as i64), None).await?;
        self.convert_to_summaries(results).await
    }

    async fn find_by_scale(&self, user_id: Uuid, scale: &str, limit: usize) -> Result<Vec<EntitySummary>, ToolError> {
        let spatial_scale = match scale {
            "Cosmic" => SpatialScale::Cosmic,
            "Planetary" => SpatialScale::Planetary,
            "Intimate" => SpatialScale::Intimate,
            _ => return Err(ToolError::InvalidParams(format!("Invalid scale: {}", scale))),
        };

        let queries = vec![ComponentQuery::ComponentDataEquals(
            "SpatialArchetype".to_string(),
            "scale".to_string(),
            json!(spatial_scale),
        )];

        let results = self.entity_manager.query_entities(user_id, queries, Some(limit as i64), None).await?;
        self.convert_to_summaries(results).await
    }

    async fn find_by_parent(&self, user_id: Uuid, parent_id: Uuid, limit: usize) -> Result<Vec<EntitySummary>, ToolError> {
        let queries = vec![ComponentQuery::ComponentDataEquals(
            "ParentLink".to_string(),
            "parent_entity_id".to_string(),
            json!(parent_id.to_string()),
        )];

        let results = self.entity_manager.query_entities(user_id, queries, Some(limit as i64), None).await?;
        self.convert_to_summaries(results).await
    }

    async fn find_by_component(&self, user_id: Uuid, component_type: &str, limit: usize) -> Result<Vec<EntitySummary>, ToolError> {
        let queries = vec![ComponentQuery::HasComponent(component_type.to_string())];

        let results = self.entity_manager.query_entities(user_id, queries, Some(limit as i64), None).await?;
        self.convert_to_summaries(results).await
    }

    async fn find_by_advanced_query(&self, user_id: Uuid, queries: Vec<ComponentQueryInput>, limit: usize) -> Result<Vec<EntitySummary>, ToolError> {
        let component_queries: Vec<ComponentQuery> = queries.into_iter().map(|q| {
            if q.has_component.unwrap_or(true) {
                ComponentQuery::HasComponent(q.component_type)
            } else if let (Some(path), Some(value)) = (q.field_path, q.field_value) {
                ComponentQuery::ComponentDataEquals(q.component_type, path, value)
            } else {
                ComponentQuery::HasComponent(q.component_type)
            }
        }).collect();

        let results = self.entity_manager.query_entities(user_id, component_queries, Some(limit as i64), None).await?;
        self.convert_to_summaries(results).await
    }

    async fn convert_to_summaries(&self, results: Vec<crate::services::EntityQueryResult>) -> Result<Vec<EntitySummary>, ToolError> {
        let mut summaries = Vec::new();

        for result in results {
            // Convert Vec<EcsComponent> to a component lookup map
            let mut component_map = std::collections::HashMap::new();
            for comp in &result.components {
                component_map.insert(comp.component_type.clone(), &comp.component_data);
            }

            let name = component_map.get("Name")
                .and_then(|c| c.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("Unknown")
                .to_string();

            let scale = component_map.get("SpatialArchetype")
                .and_then(|c| c.get("scale"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());

            let position = component_map.get("Position")
                .or_else(|| component_map.get("EnhancedPosition"))
                .and_then(|pos| {
                    let x = pos.get("x")?.as_f64()?;
                    let y = pos.get("y")?.as_f64()?;
                    let z = pos.get("z")?.as_f64()?;
                    Some(PositionSummary { x, y, z, scale: scale.clone() })
                });

            let parent_id = component_map.get("ParentLink")
                .and_then(|c| c.get("parent_entity_id"))
                .and_then(|p| p.as_str())
                .map(|s| s.to_string());

            let component_types: Vec<String> = result.components.iter()
                .map(|c| c.component_type.clone())
                .collect();

            summaries.push(EntitySummary {
                entity_id: result.entity.id.to_string(),
                name,
                scale,
                position,
                parent_id,
                component_types,
            });
        }

        Ok(summaries)
    }
}

/// Tool for getting detailed information about a specific entity
#[derive(Clone)]
pub struct GetEntityDetailsTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl GetEntityDetailsTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input parameters for getting entity details
#[derive(Debug, Deserialize)]
pub struct GetEntityDetailsInput {
    /// User ID performing the operation
    pub user_id: String,
    /// Entity ID to get details for
    pub entity_id: String,
    /// Whether to include hierarchy information
    pub include_hierarchy: Option<bool>,
    /// Whether to include relationship information
    pub include_relationships: Option<bool>,
}

/// Detailed entity information output
#[derive(Debug, Serialize)]
pub struct EntityDetailsOutput {
    pub entity_id: String,
    pub name: String,
    pub components: serde_json::Map<String, JsonValue>,
    pub hierarchy_path: Option<Vec<HierarchyLevel>>,
    pub children: Option<Vec<EntitySummary>>,
    pub relationships: Option<Vec<RelationshipInfo>>,
}

/// Information about entity relationships
#[derive(Debug, Serialize)]
pub struct RelationshipInfo {
    pub target_entity_id: String,
    pub target_name: String,
    pub relationship_type: String,
    pub strength: Option<f64>,
}

/// Hierarchy level information (reused from hierarchy_tools)
#[derive(Debug, Serialize)]
pub struct HierarchyLevel {
    pub entity_id: String,
    pub name: String,
    pub scale: Option<String>,
    pub level: u32,
    pub depth_from_root: u32,
    pub relationship: Option<String>,
}

#[async_trait]
impl ScribeTool for GetEntityDetailsTool {
    fn name(&self) -> &'static str {
        "get_entity_details"
    }

    fn description(&self) -> &'static str {
        "Get detailed information about a specific entity, including all components, \
         optional hierarchy path, children, and relationships."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the operation"
                },
                "entity_id": {
                    "type": "string",
                    "description": "UUID of the entity to get details for"
                },
                "include_hierarchy": {
                    "type": "boolean",
                    "default": false,
                    "description": "Whether to include hierarchy path information"
                },
                "include_relationships": {
                    "type": "boolean",
                    "default": false,
                    "description": "Whether to include relationship information"
                }
            },
            "required": ["user_id", "entity_id"]
        })
    }

    #[instrument(skip(self, params), fields(tool = "get_entity_details"))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        let input: GetEntityDetailsInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;

        let entity_id = Uuid::parse_str(&input.entity_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid entity_id: {}", e)))?;

        info!("Getting details for entity {} for user {}", entity_id, user_id);

        // Get the main entity
        let entity = self.entity_manager.get_entity(user_id, entity_id).await?
            .ok_or_else(|| ToolError::ExecutionFailed(format!("Entity {} not found", entity_id)))?;

        // Convert components to map for easier access
        let mut component_map = std::collections::HashMap::new();
        for comp in &entity.components {
            component_map.insert(comp.component_type.clone(), &comp.component_data);
        }

        let name = component_map.get("Name")
            .and_then(|c| c.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("Unknown")
            .to_string();

        // Get hierarchy information if requested
        let hierarchy_path = if input.include_hierarchy.unwrap_or(false) {
            match self.entity_manager.get_entity_hierarchy_path(user_id, entity_id).await {
                Ok(path) => Some(path.into_iter().map(|h| HierarchyLevel {
                    entity_id: h.entity_id.to_string(),
                    name: h.name,
                    scale: h.scale.map(|s| format!("{:?}", s)),
                    level: h.hierarchical_level,
                    depth_from_root: h.depth_from_root,
                    relationship: h.relationship,
                }).collect()),
                Err(e) => {
                    debug!("Failed to get hierarchy path: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Get children entities
        let children = if hierarchy_path.is_some() {
            let queries = vec![ComponentQuery::ComponentDataEquals(
                "ParentLink".to_string(),
                "parent_entity_id".to_string(),
                json!(entity_id.to_string()),
            )];

            match self.entity_manager.query_entities(user_id, queries, Some(50), None).await {
                Ok(results) => Some(FindEntityTool::new(self.entity_manager.clone()).convert_to_summaries(results).await?),
                Err(e) => {
                    debug!("Failed to get children: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Get relationships if requested
        let relationships = if input.include_relationships.unwrap_or(false) {
            match component_map.get("Relationships") {
                Some(rel_component) => {
                    if let Some(relationships_array) = rel_component.get("relationships").and_then(|r| r.as_array()) {
                        let mut rel_info = Vec::new();
                        for rel in relationships_array {
                            if let (Some(target_id), Some(rel_type)) = (
                                rel.get("target_entity_id").and_then(|t| t.as_str()),
                                rel.get("relationship_type").and_then(|t| t.as_str()),
                            ) {
                                let target_uuid = Uuid::parse_str(target_id).ok();
                                let target_name = if let Some(target_uuid) = target_uuid {
                                    match self.entity_manager.get_entity(user_id, target_uuid).await {
                                        Ok(Some(target_entity)) => {
                                            let mut target_comp_map = std::collections::HashMap::new();
                                            for comp in &target_entity.components {
                                                target_comp_map.insert(comp.component_type.clone(), &comp.component_data);
                                            }
                                            target_comp_map.get("Name")
                                                .and_then(|c| c.get("name"))
                                                .and_then(|n| n.as_str())
                                                .map(|s| s.to_string())
                                                .unwrap_or_else(|| "Unknown".to_string())
                                        },
                                        _ => "Unknown".to_string(),
                                    }
                                } else {
                                    "Unknown".to_string()
                                };

                                let strength = rel.get("trust").and_then(|s| s.as_f64());

                                rel_info.push(RelationshipInfo {
                                    target_entity_id: target_id.to_string(),
                                    target_name,
                                    relationship_type: rel_type.to_string(),
                                    strength,
                                });
                            }
                        }
                        Some(rel_info)
                    } else {
                        None
                    }
                },
                None => None,
            }
        } else {
            None
        };

        // Convert components back to the expected map format
        let components_output: serde_json::Map<String, JsonValue> = entity.components.iter()
            .map(|comp| (comp.component_type.clone(), comp.component_data.clone()))
            .collect();

        let output = EntityDetailsOutput {
            entity_id: entity_id.to_string(),
            name,
            components: components_output,
            hierarchy_path,
            children,
            relationships,
        };

        info!("Retrieved details for entity {}", entity_id);
        Ok(serde_json::to_value(output)?)
    }
}