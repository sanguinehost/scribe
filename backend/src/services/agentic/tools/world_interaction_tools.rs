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
use tracing::{info, debug, instrument};

use crate::{
    services::{EcsEntityManager, ComponentQuery, EntityQueryResult, ComponentUpdate, ComponentOperation},
    models::ecs::{SpatialScale, SalienceTier, ParentLinkComponent},
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

        debug!("Found {} entities", output.total_found);
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

/// Tool for creating new entities in the world
#[derive(Clone)]
pub struct CreateEntityTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl CreateEntityTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input parameters for creating entities
#[derive(Debug, Deserialize)]
pub struct CreateEntityInput {
    /// User ID performing the operation
    pub user_id: String,
    /// Name for the entity
    pub entity_name: String,
    /// Archetype signature (e.g., "Name|Position|SpatialArchetype")
    pub archetype_signature: String,
    /// Component data for the entity
    pub components: serde_json::Map<String, JsonValue>,
    /// Optional parent entity ID for hierarchical relationships
    pub parent_entity_id: Option<String>,
    /// Optional salience tier (Core, Secondary, Flavor)
    pub salience_tier: Option<String>,
}

/// Output from entity creation
#[derive(Debug, Serialize)]
pub struct CreateEntityOutput {
    /// ID of the newly created entity
    pub entity_id: String,
    /// Name of the entity
    pub name: String,
    /// Whether creation was successful
    pub created: bool,
    /// Parent entity ID if applicable
    pub parent_id: Option<String>,
    /// Salience tier if set
    pub salience: Option<String>,
    /// Message about the creation
    pub message: String,
}

#[async_trait]
impl ScribeTool for CreateEntityTool {
    fn name(&self) -> &'static str {
        "create_entity"
    }

    fn description(&self) -> &'static str {
        "Creates a new entity in the world with specified components. \
         Supports hierarchical relationships via parent_entity_id and \
         salience management for narrative importance."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user performing the operation"
                },
                "entity_name": {
                    "type": "string",
                    "description": "Name for the new entity"
                },
                "archetype_signature": {
                    "type": "string",
                    "description": "Pipe-separated list of component types (e.g., 'Name|Position|SpatialArchetype')"
                },
                "components": {
                    "type": "object",
                    "description": "Component data keyed by component type",
                    "additionalProperties": true
                },
                "parent_entity_id": {
                    "type": "string",
                    "description": "Optional UUID of parent entity for hierarchical relationships"
                },
                "salience_tier": {
                    "type": "string",
                    "enum": ["Core", "Secondary", "Flavor"],
                    "description": "Optional salience tier for narrative importance"
                }
            },
            "required": ["user_id", "entity_name", "archetype_signature", "components"]
        })
    }

    #[instrument(skip(self, params), fields(tool = self.name()))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing create_entity with input: {}", params);
        
        // Parse input
        let input_params: CreateEntityInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input parameters: {}", e)))?;

        // Define valid component types
        const VALID_COMPONENT_TYPES: &[&str] = &[
            "Health", "Position", "EnhancedPosition", "Inventory", "Relationships",
            "Name", "ParentLink", "SpatialArchetype", "Temporal", "Salience", "Spatial"
        ];

        // Validate component types in archetype signature
        let archetype_components: Vec<&str> = input_params.archetype_signature.split('|')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        for comp_type in &archetype_components {
            if !VALID_COMPONENT_TYPES.contains(comp_type) {
                return Err(ToolError::InvalidParams(format!("Invalid component type in archetype: {}", comp_type)));
            }
        }

        // Validate component data keys match archetype
        for comp_type in input_params.components.keys() {
            if !archetype_components.contains(&comp_type.as_str()) {
                return Err(ToolError::InvalidParams(format!(
                    "Component '{}' not listed in archetype signature", comp_type
                )));
            }
        }

        // Validate component data schema for known types
        for (comp_type, comp_data) in &input_params.components {
            match comp_type.as_str() {
                "Name" => {
                    if !comp_data.get("name").and_then(|v| v.as_str()).is_some() {
                        return Err(ToolError::InvalidParams(format!(
                            "Name component requires 'name' field"
                        )));
                    }
                }
                "Position" => {
                    if !comp_data.get("x").and_then(|v| v.as_f64()).is_some() ||
                       !comp_data.get("y").and_then(|v| v.as_f64()).is_some() ||
                       !comp_data.get("z").and_then(|v| v.as_f64()).is_some() ||
                       !comp_data.get("zone").and_then(|v| v.as_str()).is_some() {
                        return Err(ToolError::InvalidParams(format!(
                            "Position component requires 'x', 'y', 'z' (numbers) and 'zone' (string) fields"
                        )));
                    }
                }
                "SpatialArchetype" => {
                    if !comp_data.get("scale").and_then(|v| v.as_str()).is_some() ||
                       !comp_data.get("hierarchical_level").and_then(|v| v.as_u64()).is_some() ||
                       !comp_data.get("level_name").and_then(|v| v.as_str()).is_some() {
                        return Err(ToolError::InvalidParams(format!(
                            "SpatialArchetype component requires 'scale', 'hierarchical_level', and 'level_name' fields"
                        )));
                    }
                    
                    // Validate scale value
                    let scale = comp_data.get("scale").and_then(|v| v.as_str()).unwrap();
                    if !matches!(scale, "Cosmic" | "Planetary" | "Intimate") {
                        return Err(ToolError::InvalidParams(format!(
                            "Invalid scale value: {}. Must be Cosmic, Planetary, or Intimate", scale
                        )));
                    }
                }
                "Temporal" => {
                    if !comp_data.get("temporal_mode").and_then(|v| v.as_str()).is_some() {
                        return Err(ToolError::InvalidParams(format!(
                            "Temporal component requires 'temporal_mode' field"
                        )));
                    }
                }
                // ParentLink and Salience are handled specially later
                "ParentLink" | "Salience" => {}
                // For other components, we'll allow them through for now
                _ => {}
            }
        }

        // Parse user ID
        let user_id = Uuid::parse_str(&input_params.user_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid user_id UUID: {}", input_params.user_id)))?;

        // Parse parent entity ID if provided
        let parent_entity_id = if let Some(parent_id_str) = &input_params.parent_entity_id {
            Some(Uuid::parse_str(parent_id_str)
                .map_err(|_| ToolError::InvalidParams(format!("Invalid parent_entity_id UUID: {}", parent_id_str)))?)
        } else {
            None
        };

        // Validate parent entity ownership if provided
        if let Some(parent_id) = parent_entity_id {
            let parent_result = self.entity_manager.get_entity(user_id, parent_id).await
                .map_err(|e| ToolError::ExecutionFailed(format!("Failed to validate parent entity: {}", e)))?;
            
            if parent_result.is_none() {
                return Err(ToolError::ExecutionFailed(format!("Parent entity {} not found or not owned by user", parent_id)));
            }
        }

        // Parse salience tier if provided
        let salience_tier = if let Some(tier_str) = &input_params.salience_tier {
            Some(match tier_str.as_str() {
                "Core" => SalienceTier::Core,
                "Secondary" => SalienceTier::Secondary,
                "Flavor" => SalienceTier::Flavor,
                _ => return Err(ToolError::InvalidParams(format!("Invalid salience tier: {}", tier_str))),
            })
        } else {
            None
        };

        // Prepare components
        let mut components: Vec<(String, JsonValue)> = Vec::new();
        
        // Add user-provided components
        for (comp_type, comp_data) in input_params.components {
            components.push((comp_type, comp_data));
        }

        // Add ParentLink component if parent is specified
        if let Some(parent_id) = parent_entity_id {
            let parent_link = ParentLinkComponent {
                parent_entity_id: parent_id,
                depth_from_root: 1, // Will be updated by entity manager
                spatial_relationship: "contained_within".to_string(),
            };
            components.push(("ParentLink".to_string(), serde_json::to_value(parent_link)?));
        }

        // Create entity
        let entity_result = if let Some(tier) = salience_tier {
            // Extract spatial scale from components if available
            let spatial_scale = components.iter()
                .find(|(t, _)| t == "SpatialArchetype")
                .and_then(|(_, data)| data.get("scale"))
                .and_then(|s| s.as_str())
                .and_then(|s| match s {
                    "Cosmic" => Some(SpatialScale::Cosmic),
                    "Planetary" => Some(SpatialScale::Planetary),
                    "Intimate" => Some(SpatialScale::Intimate),
                    _ => None,
                });

            self.entity_manager.create_entity_with_salience(
                user_id,
                None, // Let entity manager generate ID
                input_params.archetype_signature.clone(),
                tier,
                spatial_scale,
                components,
            ).await
        } else {
            self.entity_manager.create_entity(
                user_id,
                None, // Let entity manager generate ID
                input_params.archetype_signature.clone(),
                components,
            ).await
        };

        let entity = entity_result.map_err(|e| ToolError::AppError(e))?;

        let output = CreateEntityOutput {
            entity_id: entity.entity.id.to_string(),
            name: input_params.entity_name.clone(),
            created: true,
            parent_id: parent_entity_id.map(|id| id.to_string()),
            salience: input_params.salience_tier,
            message: format!("Successfully created entity '{}'", input_params.entity_name),
        };

        info!("Created entity {} with name '{}'", entity.entity.id, input_params.entity_name);
        Ok(serde_json::to_value(output)?)
    }
}

/// Tool for updating existing entities
#[derive(Clone)]
pub struct UpdateEntityTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl UpdateEntityTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input parameters for updating entities
#[derive(Debug, Deserialize)]
pub struct UpdateEntityInput {
    /// User ID performing the operation
    pub user_id: String,
    /// ID of the entity to update
    pub entity_id: String,
    /// List of component updates
    pub updates: Vec<ComponentUpdateInput>,
}

/// Component update specification
#[derive(Debug, Deserialize)]
pub struct ComponentUpdateInput {
    /// Type of component to update
    pub component_type: String,
    /// Operation to perform (Add, Update, Remove)
    pub operation: String,
    /// Component data (not required for Remove operation)
    pub data: Option<JsonValue>,
}

/// Output from entity update
#[derive(Debug, Serialize)]
pub struct UpdateEntityOutput {
    /// ID of the updated entity
    pub entity_id: String,
    /// List of components that were updated
    pub updated_components: Vec<UpdatedComponentInfo>,
    /// Whether update was successful
    pub success: bool,
    /// Message about the update
    pub message: String,
}

/// Information about an updated component
#[derive(Debug, Serialize)]
pub struct UpdatedComponentInfo {
    pub component_type: String,
    pub operation: String,
}

#[async_trait]
impl ScribeTool for UpdateEntityTool {
    fn name(&self) -> &'static str {
        "update_entity"
    }

    fn description(&self) -> &'static str {
        "Updates components of an existing entity. Supports adding new components, \
         updating existing ones, or removing components. Only entities owned by the \
         user can be modified."
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
                    "description": "UUID of the entity to update"
                },
                "updates": {
                    "type": "array",
                    "description": "List of component updates to perform",
                    "items": {
                        "type": "object",
                        "properties": {
                            "component_type": {
                                "type": "string",
                                "description": "Type of component to update"
                            },
                            "operation": {
                                "type": "string",
                                "enum": ["Add", "Update", "Remove"],
                                "description": "Operation to perform on the component"
                            },
                            "data": {
                                "type": "object",
                                "description": "Component data (not required for Remove operation)"
                            }
                        },
                        "required": ["component_type", "operation"]
                    }
                }
            },
            "required": ["user_id", "entity_id", "updates"]
        })
    }

    #[instrument(skip(self, params), fields(tool = self.name()))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing update_entity with input: {}", params);
        
        // Parse input
        let input_params: UpdateEntityInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input parameters: {}", e)))?;

        // Parse user ID
        let user_id = Uuid::parse_str(&input_params.user_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid user_id UUID: {}", input_params.user_id)))?;

        // Parse entity ID
        let entity_id = Uuid::parse_str(&input_params.entity_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid entity_id UUID: {}", input_params.entity_id)))?;

        // Verify entity exists and is owned by user
        let entity_result = self.entity_manager.get_entity(user_id, entity_id).await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to find entity: {}", e)))?;
        
        if entity_result.is_none() {
            return Err(ToolError::ExecutionFailed(format!("Entity {} not found or not owned by user", entity_id)));
        }

        // Prepare component updates
        let mut component_updates: Vec<ComponentUpdate> = Vec::new();
        let mut updated_info: Vec<UpdatedComponentInfo> = Vec::new();

        for update in input_params.updates {
            // Parse operation
            let operation = match update.operation.as_str() {
                "Add" => ComponentOperation::Add,
                "Update" => ComponentOperation::Update,
                "Remove" => ComponentOperation::Remove,
                _ => return Err(ToolError::InvalidParams(format!("Invalid operation: {}", update.operation))),
            };

            // Validate data is provided for Add/Update operations
            if matches!(operation, ComponentOperation::Add | ComponentOperation::Update) && update.data.is_none() {
                return Err(ToolError::InvalidParams(format!(
                    "Component data required for {} operation on {}",
                    update.operation, update.component_type
                )));
            }

            let component_data = update.data.unwrap_or(json!({}));

            component_updates.push(ComponentUpdate {
                entity_id,
                component_type: update.component_type.clone(),
                component_data,
                operation,
            });

            updated_info.push(UpdatedComponentInfo {
                component_type: update.component_type,
                operation: update.operation,
            });
        }

        // Execute updates
        self.entity_manager.update_components(user_id, entity_id, component_updates).await
            .map_err(|e| ToolError::AppError(e))?;

        let output = UpdateEntityOutput {
            entity_id: entity_id.to_string(),
            updated_components: updated_info,
            success: true,
            message: format!("Successfully updated entity {}", entity_id),
        };

        info!("Updated entity {} with {} component changes", entity_id, output.updated_components.len());
        Ok(serde_json::to_value(output)?)
    }
}

/// Tool for getting contained entities within a parent (spatial hierarchy queries)
#[derive(Clone)]
pub struct GetContainedEntitiesTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl GetContainedEntitiesTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input parameters for getting contained entities
#[derive(Debug, Deserialize)]
pub struct GetContainedEntitiesInput {
    /// User ID performing the operation
    pub user_id: String,
    /// ID of the parent entity to query
    pub parent_entity_id: String,
    /// Query options
    pub options: Option<ContainedEntitiesOptions>,
}

/// Options for contained entities queries
#[derive(Debug, Deserialize)]
pub struct ContainedEntitiesOptions {
    /// Maximum depth to traverse (null for unlimited)
    pub depth: Option<u32>,
    /// Whether to include the parent entity in results
    pub include_parent: Option<bool>,
    /// Filter by spatial scale
    pub scale_filter: Option<String>,
    /// Filter by component type
    pub component_filter: Option<String>,
    /// Maximum number of results
    pub limit: Option<usize>,
}

/// Output from contained entities query
#[derive(Debug, Serialize)]
pub struct GetContainedEntitiesOutput {
    /// Parent entity ID
    pub parent_id: String,
    /// List of contained entities
    pub entities: Vec<ContainedEntityInfo>,
    /// Total count of entities found
    pub total_count: usize,
    /// Whether results were truncated due to limit
    pub truncated: bool,
}

/// Information about a contained entity
#[derive(Debug, Serialize)]
pub struct ContainedEntityInfo {
    pub entity_id: String,
    pub name: String,
    pub depth_from_parent: u32,
    pub scale: Option<String>,
    pub component_types: Vec<String>,
    pub parent_id: Option<String>,
}

#[async_trait]
impl ScribeTool for GetContainedEntitiesTool {
    fn name(&self) -> &'static str {
        "get_contained_entities"
    }

    fn description(&self) -> &'static str {
        "Retrieves entities contained within a parent entity, supporting hierarchical \
         traversal with depth control, scale filtering, and component filtering. \
         Useful for exploring spatial hierarchies and entity relationships."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user performing the operation"
                },
                "parent_entity_id": {
                    "type": "string",
                    "description": "UUID of the parent entity to query"
                },
                "options": {
                    "type": "object",
                    "description": "Query options",
                    "properties": {
                        "depth": {
                            "type": ["integer", "null"],
                            "description": "Maximum depth to traverse (1 for immediate children, null for all descendants)",
                            "minimum": 1
                        },
                        "include_parent": {
                            "type": "boolean",
                            "description": "Whether to include the parent entity in results",
                            "default": false
                        },
                        "scale_filter": {
                            "type": "string",
                            "enum": ["Cosmic", "Planetary", "Intimate"],
                            "description": "Filter results by spatial scale"
                        },
                        "component_filter": {
                            "type": "string",
                            "description": "Filter results to entities with this component type"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results to return",
                            "minimum": 1,
                            "maximum": 1000
                        }
                    }
                }
            },
            "required": ["user_id", "parent_entity_id"]
        })
    }

    #[instrument(skip(self, params), fields(tool = self.name()))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing get_contained_entities with input: {}", params);
        
        // Parse input
        let input_params: GetContainedEntitiesInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input parameters: {}", e)))?;

        // Parse user ID
        let user_id = Uuid::parse_str(&input_params.user_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid user_id UUID: {}", input_params.user_id)))?;

        // Parse parent entity ID
        let parent_id = Uuid::parse_str(&input_params.parent_entity_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid parent_entity_id UUID: {}", input_params.parent_entity_id)))?;

        // Verify parent entity exists and is owned by user
        let parent_result = self.entity_manager.get_entity(user_id, parent_id).await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to find parent entity: {}", e)))?;
        
        if parent_result.is_none() {
            return Err(ToolError::ExecutionFailed(format!("Parent entity {} not found or not owned by user", parent_id)));
        }

        // Parse options
        let options = input_params.options.unwrap_or(ContainedEntitiesOptions {
            depth: Some(1), // Default to immediate children only
            include_parent: Some(false),
            scale_filter: None,
            component_filter: None,
            limit: Some(100), // Default limit
        });

        let limit = options.limit.unwrap_or(100).min(1000); // Cap at 1000

        // Execute appropriate query based on options
        let results = if let Some(depth) = options.depth {
            if depth == 1 {
                // Get immediate children only
                self.entity_manager.get_children_entities(user_id, parent_id, Some(limit)).await
                    .map_err(|e| ToolError::AppError(e))?
            } else {
                // Get descendants with depth limit
                self.entity_manager.get_descendants_entities(user_id, parent_id, Some(depth), Some(limit)).await
                    .map_err(|e| ToolError::AppError(e))?
            }
        } else if let Some(scale_str) = &options.scale_filter {
            // Get descendants filtered by scale
            let scale = match scale_str.as_str() {
                "Cosmic" => SpatialScale::Cosmic,
                "Planetary" => SpatialScale::Planetary,
                "Intimate" => SpatialScale::Intimate,
                _ => return Err(ToolError::InvalidParams(format!("Invalid scale: {}", scale_str))),
            };
            self.entity_manager.get_descendants_by_scale(user_id, parent_id, scale, Some(limit)).await
                .map_err(|e| ToolError::AppError(e))?
        } else if let Some(component_type) = &options.component_filter {
            // Get descendants with specific component
            self.entity_manager.get_descendants_with_component(user_id, parent_id, &component_type, Some(limit)).await
                .map_err(|e| ToolError::AppError(e))?
        } else {
            // Get all descendants (unlimited depth)
            self.entity_manager.get_descendants_entities(user_id, parent_id, None, Some(limit)).await
                .map_err(|e| ToolError::AppError(e))?
        };

        // Convert results to output format
        let mut entities = Vec::new();
        for result in &results {
            // Extract name from components
            let name = result.components.iter()
                .find(|c| c.component_type == "Name")
                .and_then(|c| c.component_data.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("Unnamed")
                .to_string();

            // Extract scale from SpatialArchetype component
            let scale = result.components.iter()
                .find(|c| c.component_type == "SpatialArchetype")
                .and_then(|c| c.component_data.get("scale"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());

            // Extract parent from ParentLink component
            let parent_entity_id = result.components.iter()
                .find(|c| c.component_type == "ParentLink")
                .and_then(|c| c.component_data.get("parent_entity_id"))
                .and_then(|p| p.as_str())
                .map(|p| p.to_string());

            // Calculate depth from parent (this is approximate since we don't track exact depth in results)
            let depth_from_parent = if parent_entity_id.as_ref() == Some(&parent_id.to_string()) {
                1
            } else {
                2 // For deeper descendants, we'd need to track this in the query
            };

            entities.push(ContainedEntityInfo {
                entity_id: result.entity.id.to_string(),
                name,
                depth_from_parent,
                scale,
                component_types: result.components.iter().map(|c| c.component_type.clone()).collect(),
                parent_id: parent_entity_id,
            });
        }

        let total_count = entities.len();
        let truncated = total_count == limit;

        // Include parent if requested
        if options.include_parent.unwrap_or(false) {
            if let Some(parent_data) = parent_result {
                let parent_name = parent_data.components.iter()
                    .find(|c| c.component_type == "Name")
                    .and_then(|c| c.component_data.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("Unnamed")
                    .to_string();

                let parent_scale = parent_data.components.iter()
                    .find(|c| c.component_type == "SpatialArchetype")
                    .and_then(|c| c.component_data.get("scale"))
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string());

                entities.insert(0, ContainedEntityInfo {
                    entity_id: parent_id.to_string(),
                    name: parent_name,
                    depth_from_parent: 0,
                    scale: parent_scale,
                    component_types: parent_data.components.iter().map(|c| c.component_type.clone()).collect(),
                    parent_id: None,
                });
            }
        }

        let output = GetContainedEntitiesOutput {
            parent_id: parent_id.to_string(),
            entities,
            total_count,
            truncated,
        };

        info!("Retrieved {} contained entities for parent {}", total_count, parent_id);
        Ok(serde_json::to_value(output)?)
    }
}

/// Tool for getting full spatial context (ancestors and descendants)
#[derive(Clone)]
pub struct GetSpatialContextTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl GetSpatialContextTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input parameters for getting spatial context
#[derive(Debug, Deserialize)]
pub struct GetSpatialContextInput {
    /// User ID performing the operation
    pub user_id: String,
    /// ID of the entity to get context for
    pub entity_id: String,
    /// Context options
    pub options: Option<SpatialContextOptions>,
}

/// Options for spatial context queries
#[derive(Debug, Deserialize)]
pub struct SpatialContextOptions {
    /// Include ancestors up to this many levels (null for all)
    pub ancestor_levels: Option<u32>,
    /// Include descendants down to this depth (null for all)
    pub descendant_depth: Option<u32>,
    /// Include sibling entities (same parent)
    pub include_siblings: Option<bool>,
    /// Maximum descendants to return
    pub descendant_limit: Option<usize>,
}

/// Output from spatial context query
#[derive(Debug, Serialize)]
pub struct GetSpatialContextOutput {
    /// The focal entity
    pub entity: EntitySummary,
    /// Ancestor hierarchy (from root to parent)
    pub ancestors: Vec<EntitySummary>,
    /// Descendant tree
    pub descendants: Vec<ContainedEntityInfo>,
    /// Sibling entities (if requested)
    pub siblings: Option<Vec<EntitySummary>>,
    /// Full hierarchical path as string
    pub path: String,
}

#[async_trait]
impl ScribeTool for GetSpatialContextTool {
    fn name(&self) -> &'static str {
        "get_spatial_context"
    }

    fn description(&self) -> &'static str {
        "Retrieves the full spatial context for an entity, including its ancestors \
         (up the hierarchy), descendants (down the hierarchy), and optionally siblings. \
         Provides a complete view of an entity's position in the spatial hierarchy."
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
                    "description": "UUID of the entity to get context for"
                },
                "options": {
                    "type": "object",
                    "description": "Context query options",
                    "properties": {
                        "ancestor_levels": {
                            "type": ["integer", "null"],
                            "description": "Number of ancestor levels to include (null for all)",
                            "minimum": 1
                        },
                        "descendant_depth": {
                            "type": ["integer", "null"],
                            "description": "Depth of descendants to include (null for all)",
                            "minimum": 1
                        },
                        "include_siblings": {
                            "type": "boolean",
                            "description": "Whether to include sibling entities",
                            "default": false
                        },
                        "descendant_limit": {
                            "type": "integer",
                            "description": "Maximum number of descendants to return",
                            "minimum": 1,
                            "maximum": 1000
                        }
                    }
                }
            },
            "required": ["user_id", "entity_id"]
        })
    }

    #[instrument(skip(self, params), fields(tool = self.name()))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing get_spatial_context with input: {}", params);
        
        // Parse input
        let input_params: GetSpatialContextInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input parameters: {}", e)))?;

        // Parse user ID
        let user_id = Uuid::parse_str(&input_params.user_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid user_id UUID: {}", input_params.user_id)))?;

        // Parse entity ID
        let entity_id = Uuid::parse_str(&input_params.entity_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid entity_id UUID: {}", input_params.entity_id)))?;

        // Get the focal entity
        let entity_result = self.entity_manager.get_entity(user_id, entity_id).await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to find entity: {}", e)))?;
        
        let entity_data = entity_result
            .ok_or_else(|| ToolError::ExecutionFailed(format!("Entity {} not found or not owned by user", entity_id)))?;

        // Parse options
        let options = input_params.options.unwrap_or(SpatialContextOptions {
            ancestor_levels: None, // All ancestors by default
            descendant_depth: Some(2), // Two levels of descendants by default
            include_siblings: Some(false),
            descendant_limit: Some(100),
        });

        // Convert focal entity to summary
        let entity_summary = convert_to_entity_summary(&entity_data);

        // Get ancestors using existing hierarchy path method
        let hierarchy_path = self.entity_manager.get_entity_hierarchy_path(user_id, entity_id).await
            .map_err(|e| ToolError::AppError(e))?;

        let ancestors: Vec<EntitySummary> = if !hierarchy_path.is_empty() {
            let mut ancestor_list = Vec::new();
            
            // Convert ancestors to summaries (they're already in order from root to parent)
            // Skip the last element as it's the entity itself
            let ancestor_count = hierarchy_path.len().saturating_sub(1);
            for (idx, ancestor) in hierarchy_path.into_iter().take(ancestor_count).enumerate() {
                // Skip based on ancestor_levels if specified
                if let Some(levels) = options.ancestor_levels {
                    if idx >= levels as usize {
                        break;
                    }
                }
                
                // Get full entity data for each ancestor
                if let Ok(Some(ancestor_data)) = self.entity_manager.get_entity(user_id, ancestor.entity_id).await {
                    ancestor_list.push(convert_to_entity_summary(&ancestor_data));
                }
            }
            
            ancestor_list
        } else {
            Vec::new()
        };

        // Get descendants
        let descendant_limit = options.descendant_limit.unwrap_or(100).min(1000);
        let descendant_results = if let Some(depth) = options.descendant_depth {
            self.entity_manager.get_descendants_entities(user_id, entity_id, Some(depth), Some(descendant_limit)).await
                .map_err(|e| ToolError::AppError(e))?
        } else {
            self.entity_manager.get_descendants_entities(user_id, entity_id, None, Some(descendant_limit)).await
                .map_err(|e| ToolError::AppError(e))?
        };

        // Convert descendants to output format
        let descendants: Vec<ContainedEntityInfo> = descendant_results.into_iter()
            .map(|result| {
                let name = result.components.iter()
                    .find(|c| c.component_type == "Name")
                    .and_then(|c| c.component_data.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("Unnamed")
                    .to_string();

                let scale = result.components.iter()
                    .find(|c| c.component_type == "SpatialArchetype")
                    .and_then(|c| c.component_data.get("scale"))
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string());

                let parent_entity_id = result.components.iter()
                    .find(|c| c.component_type == "ParentLink")
                    .and_then(|c| c.component_data.get("parent_entity_id"))
                    .and_then(|p| p.as_str())
                    .map(|p| p.to_string());

                ContainedEntityInfo {
                    entity_id: result.entity.id.to_string(),
                    name,
                    depth_from_parent: 1, // Would need to calculate actual depth
                    scale,
                    component_types: result.components.iter().map(|c| c.component_type.clone()).collect(),
                    parent_id: parent_entity_id,
                }
            })
            .collect();

        // Get siblings if requested
        let siblings = if options.include_siblings.unwrap_or(false) {
            // Extract parent ID from focal entity
            if let Some(parent_id_str) = entity_data.components.iter()
                .find(|c| c.component_type == "ParentLink")
                .and_then(|c| c.component_data.get("parent_entity_id"))
                .and_then(|p| p.as_str()) {
                
                if let Ok(parent_id) = Uuid::parse_str(parent_id_str) {
                    // Get all children of the parent
                    let siblings_results = self.entity_manager.get_children_entities(user_id, parent_id, Some(50)).await
                        .map_err(|e| ToolError::AppError(e))?;
                    
                    // Filter out the focal entity and convert to summaries
                    let sibling_summaries: Vec<EntitySummary> = siblings_results.into_iter()
                        .filter(|r| r.entity.id != entity_id)
                        .map(|r| convert_to_entity_summary(&r))
                        .collect();
                    
                    Some(sibling_summaries)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Build hierarchical path string
        let mut path_parts = Vec::new();
        for ancestor in &ancestors {
            path_parts.push(ancestor.name.clone());
        }
        path_parts.push(entity_summary.name.clone());
        let path = path_parts.join(" > ");

        let output = GetSpatialContextOutput {
            entity: entity_summary,
            ancestors,
            descendants,
            siblings,
            path,
        };

        info!("Retrieved spatial context for entity {} with {} ancestors and {} descendants", 
              entity_id, output.ancestors.len(), output.descendants.len());
        Ok(serde_json::to_value(output)?)
    }
}

/// Helper function to convert EntityQueryResult to EntitySummary
fn convert_to_entity_summary(result: &EntityQueryResult) -> EntitySummary {
    let name = result.components.iter()
        .find(|c| c.component_type == "Name")
        .and_then(|c| c.component_data.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("Unnamed")
        .to_string();

    let scale = result.components.iter()
        .find(|c| c.component_type == "SpatialArchetype")
        .and_then(|c| c.component_data.get("scale"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());

    let position = result.components.iter()
        .find(|c| c.component_type == "Position")
        .and_then(|c| {
            let x = c.component_data.get("x")?.as_f64()?;
            let y = c.component_data.get("y")?.as_f64()?;
            let z = c.component_data.get("z")?.as_f64()?;
            Some(PositionSummary { x, y, z, scale: scale.clone() })
        });

    let parent_id = result.components.iter()
        .find(|c| c.component_type == "ParentLink")
        .and_then(|c| c.component_data.get("parent_entity_id"))
        .and_then(|p| p.as_str())
        .map(|s| s.to_string());

    EntitySummary {
        entity_id: result.entity.id.to_string(),
        name,
        scale,
        position,
        parent_id,
        component_types: result.components.iter().map(|c| c.component_type.clone()).collect(),
    }
}

/// Tool for moving entities between locations with validation
#[derive(Clone)]
pub struct MoveEntityTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl MoveEntityTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input parameters for moving entities
#[derive(Debug, Deserialize)]
pub struct MoveEntityInput {
    /// User ID performing the operation
    pub user_id: String,
    /// ID of the entity to move
    pub entity_id: String,
    /// ID of the destination entity
    pub destination_id: String,
    /// Movement options
    pub options: Option<MoveEntityToolOptions>,
}

/// Movement options for the tool
#[derive(Debug, Deserialize)]
pub struct MoveEntityToolOptions {
    /// Whether to validate scale compatibility
    pub validate_scale_compatibility: Option<bool>,
    /// Whether to validate movement path
    pub validate_movement_path: Option<bool>,
    /// Whether to validate destination capacity
    pub validate_destination_capacity: Option<bool>,
    /// Whether to update position
    pub update_position: Option<bool>,
    /// New position data
    pub new_position: Option<MoveEntityPosition>,
    /// Spatial relationship type
    pub spatial_relationship: Option<String>,
    /// Movement type
    pub movement_type: Option<String>,
}

/// Position data for movement
#[derive(Debug, Deserialize)]
pub struct MoveEntityPosition {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub zone: String,
}

/// Output from entity movement
#[derive(Debug, Serialize)]
pub struct MoveEntityOutput {
    pub success: bool,
    pub entity_id: String,
    pub old_parent_id: Option<String>,
    pub new_parent_id: String,
    pub position_updated: bool,
    pub movement_type: String,
    pub validations_performed: std::collections::HashMap<String, JsonValue>,
    pub timestamp: String,
    pub operation_type: String,
    pub user_id: String,
}

#[async_trait]
impl ScribeTool for MoveEntityTool {
    fn name(&self) -> &'static str {
        "move_entity"
    }

    fn description(&self) -> &'static str {
        "Move an entity to a new location with validation and position updates. Supports scale-aware movement with comprehensive validation."
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
                    "description": "ID of the entity to move"
                },
                "destination_id": {
                    "type": "string",
                    "description": "ID of the destination entity"
                },
                "options": {
                    "type": "object",
                    "description": "Movement options",
                    "properties": {
                        "validate_scale_compatibility": {
                            "type": "boolean",
                            "description": "Whether to validate scale compatibility"
                        },
                        "validate_movement_path": {
                            "type": "boolean", 
                            "description": "Whether to validate movement path"
                        },
                        "validate_destination_capacity": {
                            "type": "boolean",
                            "description": "Whether to validate destination capacity"
                        },
                        "update_position": {
                            "type": "boolean",
                            "description": "Whether to update position"
                        },
                        "new_position": {
                            "type": "object",
                            "description": "New position data",
                            "properties": {
                                "x": {"type": "number"},
                                "y": {"type": "number"},
                                "z": {"type": "number"},
                                "zone": {"type": "string"}
                            }
                        },
                        "spatial_relationship": {
                            "type": "string",
                            "description": "Spatial relationship type"
                        },
                        "movement_type": {
                            "type": "string",
                            "description": "Movement type"
                        }
                    }
                }
            },
            "required": ["user_id", "entity_id", "destination_id"]
        })
    }

    #[instrument(skip(self), fields(tool = "move_entity"))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        let input: MoveEntityInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid move entity parameters: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|_| ToolError::InvalidParams("Invalid user ID format".to_string()))?;

        let entity_id = Uuid::parse_str(&input.entity_id)
            .map_err(|_| ToolError::InvalidParams("Invalid entity ID format".to_string()))?;

        let destination_id = Uuid::parse_str(&input.destination_id)
            .map_err(|_| ToolError::InvalidParams("Invalid destination ID format".to_string()))?;

        // Convert tool options to EcsEntityManager options
        let options = if let Some(tool_opts) = input.options {
            Some(crate::services::MoveEntityOptions {
                validate_scale_compatibility: tool_opts.validate_scale_compatibility.unwrap_or(true),
                validate_movement_path: tool_opts.validate_movement_path.unwrap_or(true),
                validate_destination_capacity: tool_opts.validate_destination_capacity.unwrap_or(false),
                update_position: tool_opts.update_position.unwrap_or(false),
                new_position: tool_opts.new_position.map(|pos| crate::services::PositionData {
                    x: pos.x,
                    y: pos.y,
                    z: pos.z,
                    zone: pos.zone,
                }),
                spatial_relationship: tool_opts.spatial_relationship,
                movement_type: tool_opts.movement_type,
            })
        } else {
            None
        };

        // Execute the movement
        let result = self.entity_manager.move_entity(user_id, entity_id, destination_id, options).await
            .map_err(|e| {
                match &e {
                    AppError::NotFound(_) => ToolError::ExecutionFailed(format!("Entity not found: {}", e)),
                    AppError::ValidationError(_) => ToolError::ExecutionFailed(format!("Movement validation failed: {}", e)),
                    _ => ToolError::AppError(e),
                }
            })?;

        let output = MoveEntityOutput {
            success: result.success,
            entity_id: result.entity_id.to_string(),
            old_parent_id: result.old_parent_id.map(|id| id.to_string()),
            new_parent_id: result.new_parent_id.to_string(),
            position_updated: result.position_updated,
            movement_type: result.movement_type,
            validations_performed: result.validations_performed,
            timestamp: result.timestamp.to_rfc3339(),
            operation_type: "move_entity".to_string(),
            user_id: input.user_id,
        };

        info!("Successfully moved entity {} to destination {} for user {}", 
              entity_id, destination_id, user_id);

        Ok(serde_json::to_value(output)?)
    }
}

// ============================================================================
// Inventory Management Tools (Task 2.4)
// ============================================================================

/// Tool for adding items to entity inventories
#[derive(Clone)]
pub struct AddItemToInventoryTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl AddItemToInventoryTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input parameters for adding items to inventory
#[derive(Debug, Deserialize)]
pub struct AddItemToInventoryInput {
    /// User ID performing the operation
    pub user_id: String,
    /// ID of the character entity with inventory
    pub character_entity_id: String,
    /// ID of the item entity to add
    pub item_entity_id: String,
    /// Quantity of the item to add
    pub quantity: u32,
    /// Optional inventory slot (if supported)
    pub slot: Option<usize>,
}

/// Output from adding item to inventory
#[derive(Debug, Serialize)]
pub struct AddItemToInventoryOutput {
    /// Whether the operation succeeded
    pub success: bool,
    /// Details of the added item
    pub item_added: InventoryItemInfo,
    /// Operation type identifier
    pub operation_type: String,
    /// User ID who performed the operation
    pub user_id: String,
    /// Timestamp of operation
    pub timestamp: String,
}

/// Information about an inventory item
#[derive(Debug, Serialize)]
pub struct InventoryItemInfo {
    /// ID of the item entity
    pub entity_id: String,
    /// Quantity in inventory
    pub quantity: u32,
    /// Slot position (if any)
    pub slot: Option<usize>,
}

#[async_trait]
impl ScribeTool for AddItemToInventoryTool {
    fn name(&self) -> &'static str {
        "add_item_to_inventory"
    }

    fn description(&self) -> &'static str {
        "Add an item to a character's inventory with specified quantity and optional slot"
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "UUID of the user performing the operation"
                },
                "character_entity_id": {
                    "type": "string",
                    "description": "UUID of the character entity with inventory"
                },
                "item_entity_id": {
                    "type": "string",
                    "description": "UUID of the item entity to add"
                },
                "quantity": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Quantity of the item to add"
                },
                "slot": {
                    "type": "integer",
                    "minimum": 0,
                    "description": "Optional inventory slot position"
                }
            },
            "required": ["user_id", "character_entity_id", "item_entity_id", "quantity"]
        })
    }

    #[instrument(skip(self, params), fields(tool_name = %self.name()))]
    async fn execute(&self, params: &JsonValue) -> Result<JsonValue, ToolError> {
        let input: AddItemToInventoryInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid parameters: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|_| ToolError::InvalidParams("Invalid user ID format".to_string()))?;

        let character_id = Uuid::parse_str(&input.character_entity_id)
            .map_err(|_| ToolError::InvalidParams("Invalid character entity ID format".to_string()))?;

        let item_id = Uuid::parse_str(&input.item_entity_id)
            .map_err(|_| ToolError::InvalidParams("Invalid item entity ID format".to_string()))?;

        // Validate quantity
        if input.quantity == 0 {
            return Err(ToolError::InvalidParams("Quantity must be greater than 0".to_string()));
        }

        // Execute the inventory addition
        let result = self.entity_manager
            .add_item_to_inventory(user_id, character_id, item_id, input.quantity, input.slot)
            .await
            .map_err(|e| {
                match &e {
                    AppError::NotFound(_) => ToolError::ExecutionFailed(format!("Entity not found: {}", e)),
                    AppError::InvalidInput(_) => ToolError::ExecutionFailed(format!("Inventory operation failed: {}", e)),
                    _ => ToolError::AppError(e),
                }
            })?;

        let output = AddItemToInventoryOutput {
            success: true,
            item_added: InventoryItemInfo {
                entity_id: result.entity_id.to_string(),
                quantity: result.quantity,
                slot: result.slot,
            },
            operation_type: "add_item_to_inventory".to_string(),
            user_id: input.user_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        info!("Successfully added {} of item {} to character {} for user {}", 
              input.quantity, item_id, character_id, user_id);

        Ok(serde_json::to_value(output)?)
    }
}

/// Tool for removing items from entity inventories
#[derive(Clone)]
pub struct RemoveItemFromInventoryTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl RemoveItemFromInventoryTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input parameters for removing items from inventory
#[derive(Debug, Deserialize)]
pub struct RemoveItemFromInventoryInput {
    /// User ID performing the operation
    pub user_id: String,
    /// ID of the character entity with inventory
    pub character_entity_id: String,
    /// ID of the item entity to remove
    pub item_entity_id: String,
    /// Quantity of the item to remove
    pub quantity: u32,
}

/// Output from removing item from inventory
#[derive(Debug, Serialize)]
pub struct RemoveItemFromInventoryOutput {
    /// Whether the operation succeeded
    pub success: bool,
    /// Details of the removed item
    pub item_removed: InventoryItemInfo,
    /// Operation type identifier
    pub operation_type: String,
    /// User ID who performed the operation
    pub user_id: String,
    /// Timestamp of operation
    pub timestamp: String,
}

#[async_trait]
impl ScribeTool for RemoveItemFromInventoryTool {
    fn name(&self) -> &'static str {
        "remove_item_from_inventory"
    }

    fn description(&self) -> &'static str {
        "Remove a specified quantity of an item from a character's inventory"
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "UUID of the user performing the operation"
                },
                "character_entity_id": {
                    "type": "string",
                    "description": "UUID of the character entity with inventory"
                },
                "item_entity_id": {
                    "type": "string",
                    "description": "UUID of the item entity to remove"
                },
                "quantity": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Quantity of the item to remove"
                }
            },
            "required": ["user_id", "character_entity_id", "item_entity_id", "quantity"]
        })
    }

    #[instrument(skip(self, params), fields(tool_name = %self.name()))]
    async fn execute(&self, params: &JsonValue) -> Result<JsonValue, ToolError> {
        let input: RemoveItemFromInventoryInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid parameters: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|_| ToolError::InvalidParams("Invalid user ID format".to_string()))?;

        let character_id = Uuid::parse_str(&input.character_entity_id)
            .map_err(|_| ToolError::InvalidParams("Invalid character entity ID format".to_string()))?;

        let item_id = Uuid::parse_str(&input.item_entity_id)
            .map_err(|_| ToolError::InvalidParams("Invalid item entity ID format".to_string()))?;

        // Validate quantity
        if input.quantity == 0 {
            return Err(ToolError::InvalidParams("Quantity must be greater than 0".to_string()));
        }

        // Execute the inventory removal
        let result = self.entity_manager
            .remove_item_from_inventory(user_id, character_id, item_id, input.quantity)
            .await
            .map_err(|e| {
                match &e {
                    AppError::NotFound(_) => ToolError::ExecutionFailed(format!("Item not found: {}", e)),
                    AppError::InvalidInput(_) => ToolError::ExecutionFailed(format!("Insufficient quantity: {}", e)),
                    _ => ToolError::AppError(e),
                }
            })?;

        let output = RemoveItemFromInventoryOutput {
            success: true,
            item_removed: InventoryItemInfo {
                entity_id: result.entity_id.to_string(),
                quantity: result.quantity,
                slot: result.slot,
            },
            operation_type: "remove_item_from_inventory".to_string(),
            user_id: input.user_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        info!("Successfully removed {} of item {} from character {} for user {}", 
              input.quantity, item_id, character_id, user_id);

        Ok(serde_json::to_value(output)?)
    }
}

// ============================================================================
// Relationship Management Tools (Task 2.4)
// ============================================================================

/// Tool for updating entity relationships
#[derive(Clone)]
pub struct UpdateRelationshipTool {
    entity_manager: Arc<EcsEntityManager>,
}

impl UpdateRelationshipTool {
    pub fn new(entity_manager: Arc<EcsEntityManager>) -> Self {
        Self { entity_manager }
    }
}

/// Input parameters for updating relationships
#[derive(Debug, Deserialize)]
pub struct UpdateRelationshipInput {
    /// User ID performing the operation
    pub user_id: String,
    /// ID of the source entity (who has the relationship)
    pub source_entity_id: String,
    /// ID of the target entity (relationship target)
    pub target_entity_id: String,
    /// Type/description of the relationship
    pub relationship_type: String,
    /// Trust level (-1.0 to 1.0)
    pub trust: f32,
    /// Affection level (-1.0 to 1.0)
    pub affection: f32,
    /// Additional metadata about the relationship
    pub metadata: Option<JsonValue>,
}

/// Detailed relationship information for update operations
#[derive(Debug, Serialize)]
pub struct DetailedRelationshipInfo {
    pub target_entity_id: String,
    pub target_name: String,
    pub relationship_type: String,
    pub trust: f64,
    pub affection: f64,
    pub metadata: JsonValue,
}

/// Output from updating relationship
#[derive(Debug, Serialize)]
pub struct UpdateRelationshipOutput {
    /// Whether the operation succeeded
    pub success: bool,
    /// Details of the updated relationship
    pub relationship: DetailedRelationshipInfo,
    /// Operation type identifier
    pub operation_type: String,
    /// User ID who performed the operation
    pub user_id: String,
    /// Timestamp of operation
    pub timestamp: String,
}

#[async_trait]
impl ScribeTool for UpdateRelationshipTool {
    fn name(&self) -> &'static str {
        "update_relationship"
    }

    fn description(&self) -> &'static str {
        "Create or update a relationship between two entities with trust, affection, and metadata"
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "UUID of the user performing the operation"
                },
                "source_entity_id": {
                    "type": "string",
                    "description": "UUID of the source entity (who has the relationship)"
                },
                "target_entity_id": {
                    "type": "string",
                    "description": "UUID of the target entity (relationship target)"
                },
                "relationship_type": {
                    "type": "string",
                    "description": "Type or description of the relationship (e.g., 'trusts', 'fears', 'loves')"
                },
                "trust": {
                    "type": "number",
                    "minimum": -1.0,
                    "maximum": 1.0,
                    "description": "Trust level from -1.0 (complete distrust) to 1.0 (complete trust)"
                },
                "affection": {
                    "type": "number",
                    "minimum": -1.0,
                    "maximum": 1.0,
                    "description": "Affection level from -1.0 (hatred) to 1.0 (love)"
                },
                "metadata": {
                    "type": "object",
                    "description": "Additional metadata about the relationship"
                }
            },
            "required": ["user_id", "source_entity_id", "target_entity_id", "relationship_type", "trust", "affection"]
        })
    }

    #[instrument(skip(self, params), fields(tool_name = %self.name()))]
    async fn execute(&self, params: &JsonValue) -> Result<JsonValue, ToolError> {
        let input: UpdateRelationshipInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid parameters: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|_| ToolError::InvalidParams("Invalid user ID format".to_string()))?;

        let source_id = Uuid::parse_str(&input.source_entity_id)
            .map_err(|_| ToolError::InvalidParams("Invalid source entity ID format".to_string()))?;

        let target_id = Uuid::parse_str(&input.target_entity_id)
            .map_err(|_| ToolError::InvalidParams("Invalid target entity ID format".to_string()))?;

        // Validate trust and affection bounds
        if input.trust < -1.0 || input.trust > 1.0 {
            return Err(ToolError::InvalidParams(
                format!("Trust must be between -1.0 and 1.0, got: {}", input.trust)
            ));
        }
        if input.affection < -1.0 || input.affection > 1.0 {
            return Err(ToolError::InvalidParams(
                format!("Affection must be between -1.0 and 1.0, got: {}", input.affection)
            ));
        }

        // Convert metadata to HashMap
        let metadata = if let Some(meta) = input.metadata {
            if let JsonValue::Object(map) = meta {
                map.into_iter().collect()
            } else {
                return Err(ToolError::InvalidParams("Metadata must be an object".to_string()));
            }
        } else {
            std::collections::HashMap::new()
        };

        // Execute the relationship update
        let result = self.entity_manager
            .update_relationship(
                user_id,
                source_id,
                target_id,
                input.relationship_type.clone(),
                input.trust,
                input.affection,
                metadata,
            )
            .await
            .map_err(|e| {
                match &e {
                    AppError::NotFound(_) => ToolError::ExecutionFailed(format!("Entity not found: {}", e)),
                    AppError::InvalidInput(_) => ToolError::ExecutionFailed(format!("Relationship update failed: {}", e)),
                    _ => ToolError::AppError(e),
                }
            })?;

        let output = UpdateRelationshipOutput {
            success: true,
            relationship: DetailedRelationshipInfo {
                target_entity_id: result.target_entity_id.to_string(),
                target_name: result.target_entity_id.to_string(), // TODO: Get actual target name
                relationship_type: result.relationship_type,
                trust: result.trust as f64,
                affection: result.affection as f64,
                metadata: serde_json::to_value(&result.metadata)
                    .unwrap_or_else(|_| JsonValue::Object(serde_json::Map::new())),
            },
            operation_type: "update_relationship".to_string(),
            user_id: input.user_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        info!("Successfully updated relationship from {} to {} for user {}", 
              source_id, target_id, user_id);

        Ok(serde_json::to_value(output)?)
    }
}

