//! Atomic Entity CRUD Tools
//!
//! These tools provide atomic, structured operations for entity management.
//! They do NOT use AI for interpretation - that responsibility belongs to the agents.
//! Agents analyze natural language and call these tools with structured parameters.

use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::info;
use chrono::{DateTime, Utc};

use crate::{
    services::{ComponentUpdate, ComponentOperation, EcsEntityManager},
    models::ecs::{
        SpatialScale, NameComponent, 
        SpatialArchetypeComponent, HierarchicalCoordinates,
        PositionType,
    },
    models::ecs_diesel::{EcsEntity, EcsComponent},
    services::agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    services::agentic::unified_tool_registry::{
        SelfRegisteringTool, ToolCategory, ToolCapability, 
        ToolSecurityPolicy, AgentType, ToolExample, 
        DataAccessPolicy, AuditLevel,
    },
    state::AppState,
    errors::AppError,
    auth::session_dek::SessionDek,
};

// ===== ATOMIC FIND ENTITY TOOL =====

/// Atomic tool that searches for entities based on structured criteria
/// No AI interpretation - just direct database queries
#[derive(Clone)]
pub struct FindEntityTool {
    app_state: Arc<AppState>,
}

impl FindEntityTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
    
    /// Execute entity search with structured parameters
    async fn search_entities(
        &self,
        user_id: Uuid,
        entity_type: Option<String>,
        name_pattern: Option<String>,
        component_filters: Option<HashMap<String, JsonValue>>,
        spatial_filter: Option<SpatialFilter>,
        limit: Option<u32>,
    ) -> Result<Vec<EntitySearchResult>, ToolError> {
        let ecs_manager = &self.app_state.ecs_entity_manager;
        
        // Build component criteria
        let mut criteria = Vec::new();
        
        // Add component type filters
        if let Some(filters) = component_filters {
            for (component_type, _) in filters {
                criteria.push(crate::services::ecs_entity_manager::ComponentQuery::HasComponent(component_type));
            }
        }
        
        // Execute query
        let results = ecs_manager.query_entities(
            user_id,
            criteria,
            limit.map(|l| l as i64),
            None, // offset
        )
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to query entities: {}", e)))?;
        
        // Filter results based on additional criteria
        let mut filtered_results = Vec::new();
        
        for result in results {
            let mut matches = true;
            
            // Check entity type if specified
            if let Some(ref expected_type) = entity_type {
                let archetype_data = result.components.iter()
                    .find(|c| c.component_type == "SpatialArchetype")
                    .map(|c| &c.component_data);
                    
                if let Some(data) = archetype_data {
                    if let Ok(archetype) = serde_json::from_value::<SpatialArchetypeComponent>(data.clone()) {
                        if archetype.archetype_name != *expected_type {
                            matches = false;
                        }
                    }
                }
            }
            
            // Check name pattern if specified
            if matches && name_pattern.is_some() {
                let name_data = result.components.iter()
                    .find(|c| c.component_type == "Name")
                    .map(|c| &c.component_data);
                    
                if let Some(data) = name_data {
                    if let Ok(name_comp) = serde_json::from_value::<NameComponent>(data.clone()) {
                        let pattern = name_pattern.as_ref().unwrap().to_lowercase();
                        if !name_comp.name.to_lowercase().contains(&pattern) &&
                           !name_comp.display_name.to_lowercase().contains(&pattern) {
                            matches = false;
                        }
                    }
                }
            }
            
            // Check spatial filter if specified
            if matches && spatial_filter.is_some() {
                // Apply spatial filtering logic
                // TODO: Implement spatial filtering based on scale, parent_id, location_name
            }
            
            if matches {
                filtered_results.push(EntitySearchResult {
                    entity_id: result.entity.id,
                    entity_type: result.components.iter()
                        .find(|c| c.component_type == "SpatialArchetype")
                        .and_then(|c| serde_json::from_value::<SpatialArchetypeComponent>(c.component_data.clone()).ok())
                        .map(|a| a.archetype_name)
                        .unwrap_or_else(|| "Unknown".to_string()),
                    name: result.components.iter()
                        .find(|c| c.component_type == "Name")
                        .and_then(|c| serde_json::from_value::<NameComponent>(c.component_data.clone()).ok())
                        .map(|n| n.display_name)
                        .unwrap_or_else(|| "Unnamed".to_string()),
                    components: result.components.iter()
                        .map(|c| c.component_type.clone())
                        .collect(),
                });
            }
        }
        
        Ok(filtered_results)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SpatialFilter {
    pub scale: Option<String>,
    pub parent_id: Option<String>,
    pub location_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EntitySearchResult {
    pub entity_id: Uuid,
    pub entity_type: String,
    pub name: String,
    pub components: Vec<String>,
}

#[async_trait]
impl ScribeTool for FindEntityTool {
    fn name(&self) -> &'static str {
        "find_entity"
    }

    fn description(&self) -> &'static str {
        "Search for entities by type, name, components, or spatial filters. Use name_pattern for partial matches or search_by_name for exact entity resolution."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the operation"
                },
                "entity_type": {
                    "type": "string",
                    "description": "Type of entity to search for (e.g., 'character', 'location', 'item')"
                },
                "name_pattern": {
                    "type": "string",
                    "description": "Partial name to search for (substring match)"
                },
                "search_by_name": {
                    "type": "string",
                    "description": "Exact entity name to find (uses entity resolution for intelligent matching)"
                },
                "search_context": {
                    "type": "string",
                    "description": "Additional context to help resolve ambiguous entity names when using search_by_name"
                },
                "component_filters": {
                    "type": "object",
                    "description": "Component types and values to filter by",
                    "additionalProperties": true
                },
                "spatial_filter": {
                    "type": "object",
                    "properties": {
                        "scale": {"type": "string"},
                        "parent_id": {"type": "string"},
                        "location_name": {"type": "string"}
                    }
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results"
                }
            },
            "required": ["user_id"]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let user_id = Uuid::parse_str(params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        // Check if we're doing entity resolution by exact name
        if let Some(search_by_name) = params.get("search_by_name").and_then(|v| v.as_str()) {
            // Use GetEntityDetailsTool's resolution logic
            use crate::services::agentic::entity_resolution_tool::EntityResolutionTool;
            
            let resolution_tool = EntityResolutionTool::new(self.app_state.clone());
            let context = params.get("search_context").and_then(|v| v.as_str());
            
            // Get existing entities for resolution
            let existing_entities = self.app_state.ecs_entity_manager
                .query_entities(user_id, vec![], Some(100), None)
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("Failed to query entities: {}", e)))?;
            
            let mut existing_for_resolution = vec![];
            for entity in &existing_entities {
                if let Some(name_component) = entity.components.iter().find(|c| c.component_type == "Name") {
                    if let Some(name) = name_component.component_data.get("name").and_then(|n| n.as_str()) {
                        existing_for_resolution.push(json!({
                            "entity_id": entity.entity.id.to_string(),
                            "name": name,
                            "display_name": name_component.component_data.get("display_name").and_then(|n| n.as_str()).unwrap_or(name),
                            "entity_type": "unknown",
                            "context": context
                        }));
                    }
                }
            }
            
            // Call entity resolution
            let resolution_params = json!({
                "user_id": user_id.to_string(),
                "narrative_text": context.unwrap_or(search_by_name),
                "entity_names": [search_by_name],
                "existing_entities": existing_for_resolution
            });
            
            let resolution_result = resolution_tool.execute(&resolution_params, &SessionDek::new(vec![0u8; 32])).await?;
            
            // Extract resolved entity and convert to search result
            if let Some(resolved_entities) = resolution_result.get("resolved_entities").and_then(|e| e.as_array()) {
                if let Some(first_entity) = resolved_entities.first() {
                    if let Some(entity_id_str) = first_entity.get("entity_id").and_then(|id| id.as_str()) {
                        if let Ok(entity_id) = Uuid::parse_str(entity_id_str) {
                            if entity_id != Uuid::nil() {
                                let confidence = first_entity.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0);
                                if confidence > 0.7 {
                                    // Find the resolved entity in our existing entities list
                                    if let Some(entity) = existing_entities.iter().find(|e| e.entity.id == entity_id) {
                                        let name = entity.components.iter()
                                            .find(|c| c.component_type == "Name")
                                            .and_then(|c| c.component_data.get("display_name"))
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Unnamed")
                                            .to_string();
                                            
                                        let entity_type = entity.components.iter()
                                            .find(|c| c.component_type == "SpatialArchetype")
                                            .and_then(|c| c.component_data.get("archetype_name"))
                                            .and_then(|v| v.as_str())
                                            .unwrap_or("Unknown")
                                            .to_string();
                                            
                                        let result = EntitySearchResult {
                                            entity_id,
                                            entity_type,
                                            name,
                                            components: entity.components.iter().map(|c| c.component_type.clone()).collect(),
                                        };
                                        
                                        return Ok(json!({"entities": [result]}));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // If we couldn't resolve, return empty results
            return Ok(json!({"entities": []}));
        }
        
        // Extract structured parameters for regular search
        let entity_type = params.get("entity_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
            
        let name_pattern = params.get("name_pattern")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
            
        let component_filters = params.get("component_filters")
            .and_then(|v| v.as_object())
            .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
            
        let spatial_filter = params.get("spatial_filter")
            .and_then(|v| serde_json::from_value::<SpatialFilter>(v.clone()).ok());
            
        let limit = params.get("limit")
            .and_then(|v| v.as_u64())
            .map(|l| l as u32);
        
        // Execute search
        let results = self.search_entities(
            user_id,
            entity_type,
            name_pattern,
            component_filters,
            spatial_filter,
            limit,
        ).await?;
        
        Ok(serde_json::to_value(&json!({
            "found": results.len(),
            "entities": results,
        })).map_err(|e| ToolError::ExecutionFailed(format!("Failed to serialize results: {}", e)))?)
    }
}

impl SelfRegisteringTool for FindEntityTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Discovery
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "query".to_string(),
                target: "entities".to_string(),
                context: Some("by various filters".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to search for entities based on type, name, components, or spatial location".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for natural language interpretation - agents should analyze text and call with structured parameters".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Find all characters in a specific location".to_string(),
                input: json!({
                    "entity_type": "character",
                    "spatial_filter": {
                        "location_name": "Tavern"
                    }
                }),
                expected_output: "List of character entities in the Tavern".to_string(),
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
            required_capabilities: vec!["entity_management".to_string()],
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false,
                allowed_scopes: vec!["entities".to_string()],
            },
            audit_level: AuditLevel::Basic,
            rate_limit: None,
        }
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "found": {"type": "integer"},
                "entities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "entity_id": {"type": "string"},
                            "entity_type": {"type": "string"},
                            "name": {"type": "string"},
                            "components": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        }
                    }
                }
            }
        })
    }
}

// ===== ATOMIC CREATE ENTITY TOOL =====

/// Position in 3D space
#[derive(Debug, Serialize, Deserialize)]
pub struct Position {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

/// Atomic tool that creates entities with structured parameters
#[derive(Clone)]
pub struct CreateEntityTool {
    app_state: Arc<AppState>,
}

impl CreateEntityTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
    
    /// Create entity with atomic parameters
    async fn create_entity_atomic(
        &self,
        user_id: Uuid,
        entity_type: String,
        name: String,
        display_name: Option<String>,
        spatial_scale: SpatialScale,
        position: Option<Position>,
        parent_id: Option<Uuid>,
        salience_tier: Option<crate::models::ecs::SalienceTier>,
        additional_components: Option<HashMap<String, JsonValue>>,
    ) -> Result<EntityCreationOutput, ToolError> {
        let ecs_manager = &self.app_state.ecs_entity_manager;
        
        // Prepare base components
        let mut components = HashMap::new();
        
        // Clone values we'll need to use multiple times
        let display_name_value = display_name.clone().unwrap_or_else(|| name.clone());
        let spatial_scale_value = spatial_scale.clone();
        
        // Name component
        components.insert(
            "Name".to_string(),
            json!({
                "name": name,
                "display_name": display_name_value.clone(),
            })
        );
        
        // Spatial archetype component
        components.insert(
            "SpatialArchetype".to_string(),
            json!({
                "archetype_name": entity_type,
                "is_container": spatial_scale_value == SpatialScale::Planetary || spatial_scale_value == SpatialScale::Cosmic,
                "can_contain": if spatial_scale_value == SpatialScale::Intimate { vec![] } else { vec!["*"] },
                "valid_scales": vec![spatial_scale_value.clone()],
            })
        );
        
        // Position component if specified
        if let Some(pos) = position {
            let hierarchical_coords = HierarchicalCoordinates {
                x: pos.x,
                y: pos.y,
                z: pos.z,
                scale: spatial_scale_value.clone(),
                metadata: serde_json::Map::new(),
            };
            
            components.insert(
                "Position".to_string(),
                serde_json::to_value(&hierarchical_coords)
                    .map_err(|e| ToolError::ExecutionFailed(format!("Failed to serialize position: {}", e)))?
            );
        }
        
        // Parent link component if specified
        if let Some(parent) = parent_id {
            components.insert(
                "ParentLink".to_string(),
                json!({
                    "parent_id": parent,
                })
            );
        }
        
        // Salience component
        components.insert(
            "Salience".to_string(),
            json!({
                "tier": salience_tier.unwrap_or(crate::models::ecs::SalienceTier::Secondary),
            })
        );
        
        // Add any additional components
        if let Some(additional) = additional_components {
            components.extend(additional);
        }
        
        // Convert HashMap to Vec of tuples for create_entity
        let component_vec: Vec<(String, JsonValue)> = components.into_iter().collect();
        
        // Create entity with a proper archetype signature
        let archetype_signature = format!("{}:{:?}", entity_type, spatial_scale);
        
        let entity_result = ecs_manager.create_entity(
            user_id,
            None, // Let the system generate the ID
            archetype_signature,
            component_vec,
        )
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to create entity: {}", e)))?;
        
        let entity_id = entity_result.entity.id;
        
        info!("Created entity {} of type {} at scale {:?}", entity_id, entity_type, spatial_scale);
        
        Ok(EntityCreationOutput {
            entity_id,
            entity_type,
            name: display_name_value,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct EntityCreationOutput {
    pub entity_id: Uuid,
    pub entity_type: String,
    pub name: String,
}

#[async_trait]
impl ScribeTool for CreateEntityTool {
    fn name(&self) -> &'static str {
        "create_entity"
    }

    fn description(&self) -> &'static str {
        "Create a new entity with specified type, name, spatial properties, and components"
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "entity_type": {
                    "type": "string",
                    "description": "Type of entity (e.g., 'character', 'location', 'item')"
                },
                "name": {
                    "type": "string",
                    "description": "Internal name for the entity"
                },
                "display_name": {
                    "type": "string",
                    "description": "Display name (optional, defaults to name)"
                },
                "spatial_scale": {
                    "type": "string",
                    "enum": ["Cosmic", "Planetary", "Intimate"],
                    "description": "Spatial scale of the entity"
                },
                "position": {
                    "type": "object",
                    "properties": {
                        "x": {"type": "number"},
                        "y": {"type": "number"},
                        "z": {"type": "number"}
                    },
                    "description": "3D position (optional)"
                },
                "parent_id": {
                    "type": "string",
                    "description": "UUID of parent entity (optional)"
                },
                "salience_tier": {
                    "type": "string",
                    "enum": ["Core", "Primary", "Secondary", "Flavor"],
                    "description": "Importance tier (optional)"
                },
                "additional_components": {
                    "type": "object",
                    "description": "Additional components to attach",
                    "additionalProperties": true
                }
            },
            "required": ["entity_type", "name", "spatial_scale"]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let user_id = Uuid::parse_str(params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        // Extract required parameters
        let entity_type = params.get("entity_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("entity_type is required".to_string()))?
            .to_string();
            
        let name = params.get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("name is required".to_string()))?
            .to_string();
            
        let spatial_scale_str = params.get("spatial_scale")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("spatial_scale is required".to_string()))?;
            
        let spatial_scale = match spatial_scale_str {
            "Cosmic" => SpatialScale::Cosmic,
            "Planetary" => SpatialScale::Planetary,
            "Intimate" => SpatialScale::Intimate,
            _ => return Err(ToolError::InvalidParams(format!("Invalid spatial_scale: {}", spatial_scale_str))),
        };
        
        // Extract optional parameters
        let display_name = params.get("display_name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
            
        let position = params.get("position")
            .and_then(|v| serde_json::from_value::<Position>(v.clone()).ok());
            
        let parent_id = params.get("parent_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());
            
        let salience_tier = params.get("salience_tier")
            .and_then(|v| v.as_str())
            .and_then(|s| match s {
                "Core" => Some(crate::models::ecs::SalienceTier::Core),
                "Primary" => Some(crate::models::ecs::SalienceTier::Secondary),  // Primary doesn't exist, use Secondary
                "Secondary" => Some(crate::models::ecs::SalienceTier::Secondary),
                "Flavor" => Some(crate::models::ecs::SalienceTier::Flavor),
                _ => None,
            });
            
        let additional_components = params.get("additional_components")
            .and_then(|v| v.as_object())
            .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
        
        // Create entity
        let result = self.create_entity_atomic(
            user_id,
            entity_type,
            name,
            display_name,
            spatial_scale,
            position,
            parent_id,
            salience_tier,
            additional_components,
        ).await?;
        
        Ok(serde_json::to_value(&result)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to serialize result: {}", e)))?)
    }
}

impl SelfRegisteringTool for CreateEntityTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Creation
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "create".to_string(),
                target: "entity".to_string(),
                context: Some("with structured parameters".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to create a new entity with specific type, name, and spatial properties".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for natural language processing - agents should parse requirements and call with structured data".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Create a new character".to_string(),
                input: json!({
                    "entity_type": "character",
                    "name": "guard_01",
                    "display_name": "Town Guard",
                    "spatial_scale": "Intimate",
                    "salience_tier": "Secondary"
                }),
                expected_output: "Entity created with UUID".to_string(),
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
            required_capabilities: vec!["entity_creation".to_string()],
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true,
                allowed_scopes: vec!["entities".to_string()],
            },
            audit_level: AuditLevel::Detailed,
            rate_limit: None,
        }
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "entity_id": {"type": "string"},
                "entity_type": {"type": "string"},
                "name": {"type": "string"}
            }
        })
    }
}

// ===== ATOMIC UPDATE ENTITY TOOL =====

#[derive(Clone)]
pub struct UpdateEntityTool {
    app_state: Arc<AppState>,
}

impl UpdateEntityTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
    
    /// Update entity with atomic operations
    async fn update_entity_atomic(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
        updates: HashMap<String, ComponentUpdateRequest>,
    ) -> Result<EntityUpdateOutput, ToolError> {
        let ecs_manager = &self.app_state.ecs_entity_manager;
        
        // Store the update count and component types before consuming the map
        let update_count = updates.len();
        let updated_components: Vec<String> = updates.keys().cloned().collect();
        
        // Convert update requests to ComponentUpdate format
        let mut component_updates = Vec::new();
        
        for (component_type, update_req) in updates {
            component_updates.push(ComponentUpdate {
                entity_id,
                component_type: component_type.clone(),
                component_data: update_req.data.clone(),
                operation: match update_req.operation.as_str() {
                    "add" => ComponentOperation::Add,
                    "update" => ComponentOperation::Update,
                    "remove" => ComponentOperation::Remove,
                    _ => return Err(ToolError::InvalidParams(
                        format!("Invalid operation: {}", update_req.operation)
                    )),
                },
            });
        }
        
        // Execute all updates at once
        ecs_manager.update_components(
            user_id,
            entity_id,
            component_updates,
        )
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to update components: {}", e)))?;
        
        info!("Updated entity {} with {} component changes", entity_id, update_count);
        
        Ok(EntityUpdateOutput {
            entity_id,
            updated_components,
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct ComponentUpdateRequest {
    pub operation: String, // "add", "update", "remove"
    pub data: JsonValue,
}

#[derive(Debug, Serialize)]
pub struct EntityUpdateOutput {
    pub entity_id: Uuid,
    pub updated_components: Vec<String>,
}

#[async_trait]
impl ScribeTool for UpdateEntityTool {
    fn name(&self) -> &'static str {
        "update_entity"
    }

    fn description(&self) -> &'static str {
        "Update entity components with add, update, or remove operations"
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
                    "description": "UUID of the entity to update"
                },
                "updates": {
                    "type": "object",
                    "description": "Map of component type to update operation",
                    "additionalProperties": {
                        "type": "object",
                        "properties": {
                            "operation": {
                                "type": "string",
                                "enum": ["add", "update", "remove"]
                            },
                            "data": {
                                "type": "object",
                                "description": "Component data (not needed for remove)"
                            }
                        },
                        "required": ["operation"]
                    }
                }
            },
            "required": ["user_id", "entity_id", "updates"]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let user_id = Uuid::parse_str(params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        let entity_id = Uuid::parse_str(params.get("entity_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("entity_id is required".to_string()))?)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid entity_id: {}", e)))?;
        
        let updates = params.get("updates")
            .and_then(|v| v.as_object())
            .ok_or_else(|| ToolError::InvalidParams("updates is required".to_string()))?;
            
        // Parse update requests
        let mut update_map = HashMap::new();
        for (component_type, update_value) in updates {
            let update_req: ComponentUpdateRequest = serde_json::from_value(update_value.clone())
                .map_err(|e| ToolError::InvalidParams(format!("Invalid update format: {}", e)))?;
            update_map.insert(component_type.clone(), update_req);
        }
        
        // Execute update
        let result = self.update_entity_atomic(
            user_id,
            entity_id,
            update_map,
        ).await?;
        
        Ok(serde_json::to_value(&result)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to serialize result: {}", e)))?)
    }
}

impl SelfRegisteringTool for UpdateEntityTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Management
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "update".to_string(),
                target: "entity components".to_string(),
                context: Some("atomic operations".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to add, update, or remove components from an existing entity".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for complex state changes that require business logic - use specialized tools instead".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Update entity position".to_string(),
                input: json!({
                    "entity_id": "123e4567-e89b-12d3-a456-426614174000",
                    "updates": {
                        "Position": {
                            "operation": "update",
                            "data": {
                                "x": 10.0,
                                "y": 0.0,
                                "z": 5.0
                            }
                        }
                    }
                }),
                expected_output: "Entity updated successfully".to_string(),
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
            required_capabilities: vec!["entity_modification".to_string()],
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true,
                allowed_scopes: vec!["entities".to_string()],
            },
            audit_level: AuditLevel::Detailed,
            rate_limit: None,
        }
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "entity_id": {"type": "string"},
                "updated_components": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            }
        })
    }
}

// ===== ATOMIC GET ENTITY DETAILS TOOL =====

#[derive(Clone)]
pub struct GetEntityDetailsTool {
    app_state: Arc<AppState>,
}

impl GetEntityDetailsTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
    
    /// Resolve entity name to ID using the entity resolution tool
    async fn resolve_entity_name(
        &self,
        user_id: Uuid,
        entity_name: &str,
        context: Option<&str>,
    ) -> Result<Option<Uuid>, ToolError> {
        // Import entity resolution tool
        use crate::services::agentic::entity_resolution_tool::EntityResolutionTool;
        
        let resolution_tool = EntityResolutionTool::new(self.app_state.clone());
        
        // Get existing entities for the user
        let existing_entities = self.app_state.ecs_entity_manager
            .query_entities(
                user_id,
                vec![],  // No specific criteria, we want all entities
                Some(100),  // Reasonable limit
                None,
            )
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to query existing entities: {}", e)))?;
        
        // Convert to the format expected by entity resolution
        let mut existing_for_resolution = vec![];
        for entity in existing_entities {
            if let Some(name_component) = entity.components.iter().find(|c| c.component_type == "Name") {
                if let Some(name) = name_component.component_data.get("name").and_then(|n| n.as_str()) {
                    existing_for_resolution.push(json!({
                        "entity_id": entity.entity.id.to_string(),
                        "name": name,
                        "display_name": name_component.component_data.get("display_name").and_then(|n| n.as_str()).unwrap_or(name),
                        "entity_type": "unknown",  // We'll let the resolution tool figure this out
                        "context": context
                    }));
                }
            }
        }
        
        // Call entity resolution
        let resolution_params = json!({
            "user_id": user_id.to_string(),
            "narrative_text": context.unwrap_or(entity_name),
            "entity_names": [entity_name],
            "existing_entities": existing_for_resolution
        });
        
        let resolution_result = resolution_tool.execute(&resolution_params, &SessionDek::new(vec![0u8; 32])).await?;
        
        // Extract the first resolved entity
        if let Some(resolved_entities) = resolution_result.get("resolved_entities").and_then(|e| e.as_array()) {
            if let Some(first_entity) = resolved_entities.first() {
                if let Some(entity_id_str) = first_entity.get("entity_id").and_then(|id| id.as_str()) {
                    if let Ok(entity_id) = Uuid::parse_str(entity_id_str) {
                        // Check if it's a nil UUID (unresolved)
                        if entity_id != Uuid::nil() {
                            let confidence = first_entity.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0);
                            if confidence > 0.7 {  // Only accept high-confidence matches
                                return Ok(Some(entity_id));
                            }
                        }
                    }
                }
            }
        }
        
        Ok(None)
    }
    
    /// Get detailed entity information
    async fn get_entity_details(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
    ) -> Result<EntityDetails, ToolError> {
        let ecs_manager = &self.app_state.ecs_entity_manager;
        
        // Get entity with all components
        let entity_result = ecs_manager.get_entity(user_id, entity_id)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get entity: {}", e)))?
            .ok_or_else(|| ToolError::ExecutionFailed(format!("Entity not found: {}", entity_id)))?;
        
        // Build entity details
        let entity_type = entity_result.components.iter()
            .find(|c| c.component_type == "SpatialArchetype")
            .and_then(|c| c.component_data.as_object())
            .and_then(|o| o.get("archetype_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();
            
        let name = entity_result.components.iter()
            .find(|c| c.component_type == "Name")
            .and_then(|c| c.component_data.as_object())
            .and_then(|o| o.get("display_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("Unnamed")
            .to_string();
        
        let mut components = HashMap::new();
        for component in entity_result.components {
            components.insert(component.component_type.clone(), component.component_data);
        }
        
        Ok(EntityDetails {
            entity_id,
            entity_type,
            name,
            components,
            created_at: entity_result.entity.created_at,
            updated_at: entity_result.entity.updated_at,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct EntityDetails {
    pub entity_id: Uuid,
    pub entity_type: String,
    pub name: String,
    pub components: HashMap<String, JsonValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[async_trait]
impl ScribeTool for GetEntityDetailsTool {
    fn name(&self) -> &'static str {
        "get_entity_details"
    }

    fn description(&self) -> &'static str {
        "Get detailed information about an entity by ID or name. Supports entity resolution for name-based lookups."
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
                    "description": "UUID of the entity to retrieve (optional if entity_name is provided)"
                },
                "entity_name": {
                    "type": "string",
                    "description": "Name of the entity to retrieve (will be resolved to ID)"
                },
                "context": {
                    "type": "string",
                    "description": "Additional context to help resolve ambiguous entity names"
                }
            },
            "required": ["user_id"],
            "oneOf": [
                {"required": ["entity_id"]},
                {"required": ["entity_name"]}
            ]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let user_id = Uuid::parse_str(params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        // Try to get entity_id directly first
        let entity_id = if let Some(id_str) = params.get("entity_id").and_then(|v| v.as_str()) {
            Uuid::parse_str(id_str)
                .map_err(|e| ToolError::InvalidParams(format!("Invalid entity_id: {}", e)))?
        } else if let Some(entity_name) = params.get("entity_name").and_then(|v| v.as_str()) {
            // Resolve entity name to ID
            let context = params.get("context").and_then(|v| v.as_str());
            match self.resolve_entity_name(user_id, entity_name, context).await? {
                Some(resolved_id) => resolved_id,
                None => return Err(ToolError::ExecutionFailed(format!(
                    "Could not resolve entity name '{}' to an existing entity", entity_name
                )))
            }
        } else {
            return Err(ToolError::InvalidParams(
                "Either entity_id or entity_name must be provided".to_string()
            ));
        };
        
        // Get entity details
        let result = self.get_entity_details(user_id, entity_id).await?;
        
        Ok(serde_json::to_value(&result)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to serialize result: {}", e)))?)
    }
}

impl SelfRegisteringTool for GetEntityDetailsTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Discovery
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "retrieve".to_string(),
                target: "entity details".to_string(),
                context: Some("full component data".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need complete information about a specific entity".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for bulk queries - use find_entity instead".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Get full entity information".to_string(),
                input: json!({
                    "entity_id": "123e4567-e89b-12d3-a456-426614174000"
                }),
                expected_output: "Complete entity data with all components".to_string(),
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
            required_capabilities: vec!["entity_management".to_string()],
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false,
                allowed_scopes: vec!["entities".to_string()],
            },
            audit_level: AuditLevel::Basic,
            rate_limit: None,
        }
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "entity_id": {"type": "string"},
                "entity_type": {"type": "string"},
                "name": {"type": "string"},
                "components": {
                    "type": "object",
                    "additionalProperties": true
                },
                "created_at": {"type": "string"},
                "updated_at": {"type": "string"}
            }
        })
    }
}

// ===== REGISTRATION FUNCTION =====

/// Register all entity CRUD tools
pub fn register_entity_crud_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    // Register find entity tool
    let find_tool = Arc::new(FindEntityTool::new(app_state.clone()));
    UnifiedToolRegistry::register_if_not_exists(find_tool as Arc<dyn SelfRegisteringTool + Send + Sync>)?;
    
    // Register create entity tool
    let create_tool = Arc::new(CreateEntityTool::new(app_state.clone()));
    UnifiedToolRegistry::register_if_not_exists(create_tool as Arc<dyn SelfRegisteringTool + Send + Sync>)?;
    
    // Register update entity tool
    let update_tool = Arc::new(UpdateEntityTool::new(app_state.clone()));
    UnifiedToolRegistry::register_if_not_exists(update_tool as Arc<dyn SelfRegisteringTool + Send + Sync>)?;
    
    // Register get entity details tool
    let details_tool = Arc::new(GetEntityDetailsTool::new(app_state.clone()));
    UnifiedToolRegistry::register_if_not_exists(details_tool as Arc<dyn SelfRegisteringTool + Send + Sync>)?;
    
    info!("Registered 4 atomic entity CRUD tools");
    Ok(())
}

// ===== LEGACY ENTITY SUMMARY FOR BACKWARD COMPATIBILITY =====

#[derive(Debug, Serialize)]
pub struct EntitySummary {
    pub entity_id: String,  // Keep as string for compatibility  
    pub name: String,
    pub scale: Option<String>,
    pub position: Option<serde_json::Value>,  // JSON position data
    pub parent_id: Option<String>,
    pub component_types: Vec<String>,
}