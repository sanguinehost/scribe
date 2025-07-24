// backend/src/services/agentic/tools/inventory_tools.rs
//
// Inventory management tools for the Orchestrator and other agents
// Provides query and management capabilities for entity inventories

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, debug, instrument};

use crate::{
    services::{
        WorldQueryService,
        agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    },
    models::{
        Entity,
        Item,
        Component,
        ComponentType,
    },
    errors::AppError,
    PgPool,
};

/// Tool for querying entity inventories
#[derive(Clone)]
pub struct QueryInventoryTool {
    world_query_service: Arc<WorldQueryService>,
    db_pool: PgPool,
}

impl QueryInventoryTool {
    pub fn new(
        world_query_service: Arc<WorldQueryService>,
        db_pool: PgPool,
    ) -> Self {
        Self {
            world_query_service,
            db_pool,
        }
    }
    
    /// Query inventory based on different criteria
    async fn query_inventory(
        &self,
        user_id: Uuid,
        query: &InventoryQuery,
    ) -> Result<InventoryQueryResult, ToolError> {
        match query {
            InventoryQuery::ByEntity { entity_id, include_nested } => {
                let entity_uuid = Uuid::parse_str(entity_id)
                    .map_err(|e| ToolError::InvalidParams(format!("Invalid entity_id: {}", e)))?;
                
                // Get the entity
                let entity = self.world_query_service
                    .get_entity_with_components(user_id, entity_uuid)
                    .await
                    .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get entity: {}", e)))?;
                
                // Get direct inventory items
                let mut items = self.get_entity_items(user_id, entity_uuid).await?;
                
                // If include_nested, recursively get items from contained entities
                if *include_nested {
                    let nested_items = self.get_nested_inventory(user_id, entity_uuid).await?;
                    items.extend(nested_items);
                }
                
                Ok(InventoryQueryResult {
                    entity_id: entity_uuid,
                    entity_name: entity.name.clone(),
                    items,
                    total_items: items.len(),
                    query_type: if *include_nested { "nested" } else { "direct" }.to_string(),
                })
            },
            
            InventoryQuery::ByItemType { item_type, location_id } => {
                let location_uuid = location_id.as_ref()
                    .map(|id| Uuid::parse_str(id))
                    .transpose()
                    .map_err(|e| ToolError::InvalidParams(format!("Invalid location_id: {}", e)))?;
                
                // Search for items by type
                let items = self.search_items_by_type(user_id, item_type, location_uuid).await?;
                
                Ok(InventoryQueryResult {
                    entity_id: location_uuid.unwrap_or(Uuid::nil()),
                    entity_name: "Search Result".to_string(),
                    items,
                    total_items: items.len(),
                    query_type: "by_type".to_string(),
                })
            },
            
            InventoryQuery::ByTags { tags, location_id } => {
                let location_uuid = location_id.as_ref()
                    .map(|id| Uuid::parse_str(id))
                    .transpose()
                    .map_err(|e| ToolError::InvalidParams(format!("Invalid location_id: {}", e)))?;
                
                // Search for items by tags
                let items = self.search_items_by_tags(user_id, tags, location_uuid).await?;
                
                Ok(InventoryQueryResult {
                    entity_id: location_uuid.unwrap_or(Uuid::nil()),
                    entity_name: "Search Result".to_string(),
                    items,
                    total_items: items.len(),
                    query_type: "by_tags".to_string(),
                })
            },
        }
    }
    
    /// Get direct items contained by an entity
    async fn get_entity_items(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
    ) -> Result<Vec<InventoryItemInfo>, ToolError> {
        use crate::schema::{entities, items, components};
        use diesel::prelude::*;
        
        let conn = self.db_pool.get().await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get DB connection: {}", e)))?;
        
        // Get all item entities contained by this entity
        let items = conn.interact(move |conn_sync| {
            items::table
                .inner_join(entities::table.on(items::entity_id.eq(entities::id)))
                .filter(entities::user_id.eq(user_id))
                .filter(entities::spatial_parent_id.eq(entity_id))
                .select((Item::as_select(), Entity::as_select()))
                .load::<(Item, Entity)>(conn_sync)
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("Database interaction failed: {}", e)))?
        .map_err(|e| ToolError::ExecutionFailed(format!("Query failed: {}", e)))?;
        
        // Convert to inventory info
        let mut item_infos = Vec::new();
        for (item, entity) in items {
            // Get components for this item
            let entity_id = entity.id;
            let components = conn.interact(move |conn_sync| {
                components::table
                    .filter(components::entity_id.eq(entity_id))
                    .select(Component::as_select())
                    .load::<Component>(conn_sync)
            })
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get components: {}", e)))?
            .map_err(|e| ToolError::ExecutionFailed(format!("Query failed: {}", e)))?;
            
            // Extract relevant component data
            let mut tags = Vec::new();
            let mut properties = json!({});
            
            for component in components {
                match component.component_type {
                    ComponentType::Description => {
                        if let Some(desc) = component.data.get("text").and_then(|v| v.as_str()) {
                            properties["description"] = json!(desc);
                        }
                    },
                    ComponentType::Attributes => {
                        if let Some(attrs) = component.data.as_object() {
                            for (key, value) in attrs {
                                properties[format!("attr_{}", key)] = value.clone();
                            }
                        }
                    },
                    _ => {}
                }
            }
            
            item_infos.push(InventoryItemInfo {
                id: entity.id,
                name: entity.name.clone(),
                item_type: item.item_type.clone(),
                quantity: item.quantity,
                weight: item.weight,
                value: item.value,
                container_id: entity.spatial_parent_id,
                tags,
                properties,
            });
        }
        
        Ok(item_infos)
    }
    
    /// Recursively get all items in nested containers
    async fn get_nested_inventory(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
    ) -> Result<Vec<InventoryItemInfo>, ToolError> {
        use crate::schema::entities;
        use diesel::prelude::*;
        
        let conn = self.db_pool.get().await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get DB connection: {}", e)))?;
        
        // Get all child entities
        let children = conn.interact(move |conn_sync| {
            entities::table
                .filter(entities::user_id.eq(user_id))
                .filter(entities::spatial_parent_id.eq(entity_id))
                .select(Entity::as_select())
                .load::<Entity>(conn_sync)
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("Database interaction failed: {}", e)))?
        .map_err(|e| ToolError::ExecutionFailed(format!("Query failed: {}", e)))?;
        
        let mut all_items = Vec::new();
        
        // For each child, get its items and recurse
        for child in children {
            // Get direct items of this child
            let child_items = self.get_entity_items(user_id, child.id).await?;
            all_items.extend(child_items);
            
            // Recurse into this child's inventory
            let nested = self.get_nested_inventory(user_id, child.id).await?;
            all_items.extend(nested);
        }
        
        Ok(all_items)
    }
    
    /// Search for items by type across the world or within a location
    async fn search_items_by_type(
        &self,
        user_id: Uuid,
        item_type: &str,
        location_id: Option<Uuid>,
    ) -> Result<Vec<InventoryItemInfo>, ToolError> {
        use crate::schema::{entities, items};
        use diesel::prelude::*;
        
        let conn = self.db_pool.get().await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get DB connection: {}", e)))?;
        
        let item_type_clone = item_type.to_string();
        let items = conn.interact(move |conn_sync| {
            let mut query = items::table
                .inner_join(entities::table.on(items::entity_id.eq(entities::id)))
                .filter(entities::user_id.eq(user_id))
                .filter(items::item_type.eq(item_type_clone))
                .into_boxed();
            
            if let Some(loc_id) = location_id {
                query = query.filter(entities::spatial_parent_id.eq(loc_id));
            }
            
            query
                .select((Item::as_select(), Entity::as_select()))
                .load::<(Item, Entity)>(conn_sync)
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("Database interaction failed: {}", e)))?
        .map_err(|e| ToolError::ExecutionFailed(format!("Query failed: {}", e)))?;
        
        // Convert to inventory info
        let mut item_infos = Vec::new();
        for (item, entity) in items {
            item_infos.push(InventoryItemInfo {
                id: entity.id,
                name: entity.name.clone(),
                item_type: item.item_type.clone(),
                quantity: item.quantity,
                weight: item.weight,
                value: item.value,
                container_id: entity.spatial_parent_id,
                tags: vec![],
                properties: json!({}),
            });
        }
        
        Ok(item_infos)
    }
    
    /// Search for items by tags
    async fn search_items_by_tags(
        &self,
        user_id: Uuid,
        tags: &[String],
        location_id: Option<Uuid>,
    ) -> Result<Vec<InventoryItemInfo>, ToolError> {
        // TODO: Implement tag-based search when tags are added to the schema
        debug!("Tag-based inventory search not yet implemented");
        Ok(Vec::new())
    }
}

/// Input parameters for inventory queries
#[derive(Debug, Deserialize)]
pub struct QueryInventoryInput {
    /// User ID performing the query
    pub user_id: String,
    /// The query to execute
    pub query: InventoryQuery,
}

/// Types of inventory queries
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum InventoryQuery {
    /// Get inventory of a specific entity
    ByEntity {
        entity_id: String,
        include_nested: bool,
    },
    /// Search for items by type
    ByItemType {
        item_type: String,
        location_id: Option<String>,
    },
    /// Search for items by tags
    ByTags {
        tags: Vec<String>,
        location_id: Option<String>,
    },
}

/// Inventory item information
#[derive(Debug, Serialize)]
pub struct InventoryItemInfo {
    pub id: Uuid,
    pub name: String,
    pub item_type: String,
    pub quantity: i32,
    pub weight: Option<f32>,
    pub value: Option<i32>,
    pub container_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub properties: JsonValue,
}

/// Result of inventory query
#[derive(Debug, Serialize)]
pub struct InventoryQueryResult {
    pub entity_id: Uuid,
    pub entity_name: String,
    pub items: Vec<InventoryItemInfo>,
    pub total_items: usize,
    pub query_type: String,
}

#[async_trait]
impl ScribeTool for QueryInventoryTool {
    fn name(&self) -> &'static str {
        "query_inventory"
    }
    
    fn description(&self) -> &'static str {
        "Query entity inventories to see what items they contain. \
         Supports nested inventory search, item type filtering, and tag-based search."
    }
    
    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the query"
                },
                "query": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByEntity" },
                                "entity_id": { 
                                    "type": "string", 
                                    "description": "Entity UUID to get inventory for" 
                                },
                                "include_nested": {
                                    "type": "boolean",
                                    "default": true,
                                    "description": "Include items in nested containers"
                                }
                            },
                            "required": ["type", "entity_id"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByItemType" },
                                "item_type": { 
                                    "type": "string", 
                                    "description": "Type of items to search for" 
                                },
                                "location_id": {
                                    "type": "string",
                                    "description": "Optional location to search within"
                                }
                            },
                            "required": ["type", "item_type"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByTags" },
                                "tags": { 
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Tags to search for" 
                                },
                                "location_id": {
                                    "type": "string",
                                    "description": "Optional location to search within"
                                }
                            },
                            "required": ["type", "tags"]
                        }
                    ]
                }
            },
            "required": ["user_id", "query"]
        })
    }
    
    #[instrument(skip(self, params), fields(tool = "query_inventory"))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        let input: QueryInventoryInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;
        
        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        info!("Querying inventory for user {} with query: {:?}", user_id, input.query);
        
        let result = self.query_inventory(user_id, &input.query).await?;
        
        Ok(ToolResult::Success(serde_json::to_value(result)?))
    }
}

/// Tool for managing entity inventories
#[derive(Clone)]
pub struct ManageInventoryTool {
    world_query_service: Arc<WorldQueryService>,
    db_pool: PgPool,
}

impl ManageInventoryTool {
    pub fn new(
        world_query_service: Arc<WorldQueryService>,
        db_pool: PgPool,
    ) -> Self {
        Self {
            world_query_service,
            db_pool,
        }
    }
}

/// Input for managing inventories
#[derive(Debug, Deserialize)]
pub struct ManageInventoryInput {
    /// User ID performing the operation
    pub user_id: String,
    /// The operation to perform
    pub operation: InventoryOperation,
}

/// Inventory management operations
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum InventoryOperation {
    /// Move an item to a different container
    MoveItem {
        item_id: String,
        target_container_id: String,
    },
    /// Update item properties
    UpdateItem {
        item_id: String,
        updates: ItemUpdateFields,
    },
    /// Create a new item in a container
    CreateItem {
        container_id: String,
        name: String,
        item_type: String,
        quantity: i32,
        properties: Option<JsonValue>,
    },
    /// Remove an item
    RemoveItem {
        item_id: String,
    },
}

/// Fields that can be updated on an item
#[derive(Debug, Deserialize)]
pub struct ItemUpdateFields {
    pub quantity: Option<i32>,
    pub weight: Option<f32>,
    pub value: Option<i32>,
    pub properties: Option<JsonValue>,
}

/// Output from inventory management operations
#[derive(Debug, Serialize)]
pub struct ManageInventoryOutput {
    pub operation: String,
    pub success: bool,
    pub item_id: Option<Uuid>,
    pub message: String,
}

#[async_trait]
impl ScribeTool for ManageInventoryTool {
    fn name(&self) -> &'static str {
        "manage_inventory"
    }
    
    fn description(&self) -> &'static str {
        "Manage entity inventories by moving items, updating properties, \
         creating new items, or removing items from containers."
    }
    
    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the operation"
                },
                "operation": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "MoveItem" },
                                "item_id": { 
                                    "type": "string", 
                                    "description": "Item entity UUID to move" 
                                },
                                "target_container_id": {
                                    "type": "string",
                                    "description": "Target container entity UUID"
                                }
                            },
                            "required": ["type", "item_id", "target_container_id"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "UpdateItem" },
                                "item_id": { 
                                    "type": "string", 
                                    "description": "Item entity UUID to update" 
                                },
                                "updates": {
                                    "type": "object",
                                    "properties": {
                                        "quantity": { "type": "integer" },
                                        "weight": { "type": "number" },
                                        "value": { "type": "integer" },
                                        "properties": { "type": "object" }
                                    }
                                }
                            },
                            "required": ["type", "item_id", "updates"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "CreateItem" },
                                "container_id": { 
                                    "type": "string", 
                                    "description": "Container entity UUID" 
                                },
                                "name": { "type": "string" },
                                "item_type": { "type": "string" },
                                "quantity": { "type": "integer", "minimum": 1 },
                                "properties": { "type": "object" }
                            },
                            "required": ["type", "container_id", "name", "item_type", "quantity"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "RemoveItem" },
                                "item_id": { 
                                    "type": "string", 
                                    "description": "Item entity UUID to remove" 
                                }
                            },
                            "required": ["type", "item_id"]
                        }
                    ]
                }
            },
            "required": ["user_id", "operation"]
        })
    }
    
    #[instrument(skip(self, params), fields(tool = "manage_inventory"))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        let input: ManageInventoryInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;
        
        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        info!("Managing inventory for user {} with operation: {:?}", user_id, input.operation);
        
        // TODO: Implement actual inventory management operations
        // This would require updating the entity's spatial_parent_id for moves,
        // updating item components for property changes, etc.
        
        Ok(ToolResult::Success(serde_json::to_value(ManageInventoryOutput {
            operation: "placeholder".to_string(),
            success: false,
            item_id: None,
            message: "Inventory management operations not yet implemented".to_string(),
        })?))
    }
}