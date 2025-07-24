// backend/src/services/agentic/tools/lorebook_tools.rs
//
// Lorebook integration tools for the Orchestrator and other agents
// Provides intelligent search and management capabilities for lorebook entries

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, debug, warn, instrument};
use secrecy::SecretBox;

use crate::{
    services::{
        LorebookService, EncryptionService,
        agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    },
    models::{
        lorebook_dtos::{
            CreateLorebookEntryPayload, LorebookEntryResponse,
            UpdateLorebookEntryPayload,
        },
        LorebookEntry,
    },
    errors::AppError,
    PgPool,
    auth::user_store::Backend as AuthBackend,
};
use axum_login::AuthSession;

/// Tool for querying lorebook entries with intelligent search
#[derive(Clone)]
pub struct QueryLorebookTool {
    lorebook_service: Arc<LorebookService>,
    encryption_service: Arc<EncryptionService>,
    db_pool: PgPool,
}

impl QueryLorebookTool {
    pub fn new(
        lorebook_service: Arc<LorebookService>,
        encryption_service: Arc<EncryptionService>,
        db_pool: PgPool,
    ) -> Self {
        Self {
            lorebook_service,
            encryption_service,
            db_pool,
        }
    }
    
    /// Search lorebook entries by various criteria
    async fn search_entries(
        &self,
        user_id: Uuid,
        query: &LorebookQuery,
        user_dek: &SecretBox<Vec<u8>>,
    ) -> Result<Vec<LorebookEntryInfo>, ToolError> {
        use crate::schema::{lorebooks, lorebook_entries};
        use diesel::prelude::*;
        
        let conn = self.db_pool.get().await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get DB connection: {}", e)))?;
        
        match query {
            LorebookQuery::ByName { name } => {
                // Search entries by decrypted title
                let name_lower = name.to_lowercase();
                
                let entries = conn.interact(move |conn_sync| {
                    lorebook_entries::table
                        .inner_join(lorebooks::table)
                        .filter(lorebooks::user_id.eq(user_id))
                        .select(LorebookEntry::as_select())
                        .load::<LorebookEntry>(conn_sync)
                })
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("Database interaction failed: {}", e)))?
                .map_err(|e| ToolError::ExecutionFailed(format!("Query failed: {}", e)))?;
                
                // Decrypt and filter entries
                let mut matching_entries = Vec::new();
                for entry in entries {
                    let decrypted_title = String::from_utf8_lossy(
                        &self.encryption_service.decrypt(
                            &entry.entry_title_ciphertext,
                            &entry.entry_title_nonce,
                            user_dek.expose_secret(),
                        ).map_err(|e| ToolError::ExecutionFailed(format!("Decryption failed: {}", e)))?
                    ).to_string();
                    
                    if decrypted_title.to_lowercase().contains(&name_lower) {
                        let decrypted_content = String::from_utf8_lossy(
                            &self.encryption_service.decrypt(
                                &entry.entry_content_ciphertext,
                                &entry.entry_content_nonce,
                                user_dek.expose_secret(),
                            ).map_err(|e| ToolError::ExecutionFailed(format!("Decryption failed: {}", e)))?
                        ).to_string();
                        
                        matching_entries.push(LorebookEntryInfo {
                            id: entry.id,
                            lorebook_id: entry.lorebook_id,
                            title: decrypted_title,
                            content: decrypted_content,
                            tags: vec![], // TODO: Implement tags
                        });
                    }
                }
                
                Ok(matching_entries)
            },
            
            LorebookQuery::ByCategory { category } => {
                // Search by lorebook category/name
                let category_lower = category.to_lowercase();
                
                let lorebooks = conn.interact(move |conn_sync| {
                    lorebooks::table
                        .filter(lorebooks::user_id.eq(user_id))
                        .filter(lorebooks::name.ilike(format!("%{}%", category_lower)))
                        .select(lorebooks::id)
                        .load::<Uuid>(conn_sync)
                })
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("Database interaction failed: {}", e)))?
                .map_err(|e| ToolError::ExecutionFailed(format!("Query failed: {}", e)))?;
                
                if lorebooks.is_empty() {
                    return Ok(Vec::new());
                }
                
                // Get all entries from matching lorebooks
                let entries = conn.interact(move |conn_sync| {
                    lorebook_entries::table
                        .filter(lorebook_entries::lorebook_id.eq_any(lorebooks))
                        .select(LorebookEntry::as_select())
                        .load::<LorebookEntry>(conn_sync)
                })
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("Database interaction failed: {}", e)))?
                .map_err(|e| ToolError::ExecutionFailed(format!("Query failed: {}", e)))?;
                
                // Decrypt entries
                let mut result_entries = Vec::new();
                for entry in entries {
                    let decrypted_title = String::from_utf8_lossy(
                        &self.encryption_service.decrypt(
                            &entry.entry_title_ciphertext,
                            &entry.entry_title_nonce,
                            user_dek.expose_secret(),
                        ).map_err(|e| ToolError::ExecutionFailed(format!("Decryption failed: {}", e)))?
                    ).to_string();
                    
                    let decrypted_content = String::from_utf8_lossy(
                        &self.encryption_service.decrypt(
                            &entry.entry_content_ciphertext,
                            &entry.entry_content_nonce,
                            user_dek.expose_secret(),
                        ).map_err(|e| ToolError::ExecutionFailed(format!("Decryption failed: {}", e)))?
                    ).to_string();
                    
                    result_entries.push(LorebookEntryInfo {
                        id: entry.id,
                        lorebook_id: entry.lorebook_id,
                        title: decrypted_title,
                        content: decrypted_content,
                        tags: vec![],
                    });
                }
                
                Ok(result_entries)
            },
            
            LorebookQuery::ByTags { tags: _ } => {
                // TODO: Implement tag-based search when tags are added to the schema
                warn!("Tag-based search not yet implemented");
                Ok(Vec::new())
            },
            
            LorebookQuery::FullText { query } => {
                // Search in both title and content
                let query_lower = query.to_lowercase();
                
                let entries = conn.interact(move |conn_sync| {
                    lorebook_entries::table
                        .inner_join(lorebooks::table)
                        .filter(lorebooks::user_id.eq(user_id))
                        .select(LorebookEntry::as_select())
                        .load::<LorebookEntry>(conn_sync)
                })
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("Database interaction failed: {}", e)))?
                .map_err(|e| ToolError::ExecutionFailed(format!("Query failed: {}", e)))?;
                
                // Decrypt and filter entries
                let mut matching_entries = Vec::new();
                for entry in entries {
                    let decrypted_title = String::from_utf8_lossy(
                        &self.encryption_service.decrypt(
                            &entry.entry_title_ciphertext,
                            &entry.entry_title_nonce,
                            user_dek.expose_secret(),
                        ).map_err(|e| ToolError::ExecutionFailed(format!("Decryption failed: {}", e)))?
                    ).to_string();
                    
                    let decrypted_content = String::from_utf8_lossy(
                        &self.encryption_service.decrypt(
                            &entry.entry_content_ciphertext,
                            &entry.entry_content_nonce,
                            user_dek.expose_secret(),
                        ).map_err(|e| ToolError::ExecutionFailed(format!("Decryption failed: {}", e)))?
                    ).to_string();
                    
                    if decrypted_title.to_lowercase().contains(&query_lower) || 
                       decrypted_content.to_lowercase().contains(&query_lower) {
                        matching_entries.push(LorebookEntryInfo {
                            id: entry.id,
                            lorebook_id: entry.lorebook_id,
                            title: decrypted_title,
                            content: decrypted_content,
                            tags: vec![],
                        });
                    }
                }
                
                Ok(matching_entries)
            },
        }
    }
}

/// Input parameters for lorebook queries
#[derive(Debug, Deserialize)]
pub struct QueryLorebookInput {
    /// User ID performing the query
    pub user_id: String,
    /// The query to execute
    pub query: LorebookQuery,
    /// Maximum number of results to return
    pub limit: Option<usize>,
}

/// Types of lorebook queries
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum LorebookQuery {
    /// Search by entry name/title
    ByName { name: String },
    /// Search by lorebook category
    ByCategory { category: String },
    /// Search by tags
    ByTags { tags: Vec<String> },
    /// Full-text search in title and content
    FullText { query: String },
}

/// Lorebook entry information
#[derive(Debug, Serialize)]
pub struct LorebookEntryInfo {
    pub id: Uuid,
    pub lorebook_id: Uuid,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
}

/// Output from lorebook query
#[derive(Debug, Serialize)]
pub struct QueryLorebookOutput {
    pub entries: Vec<LorebookEntryInfo>,
    pub total_found: usize,
    pub query_type: String,
}

#[async_trait]
impl ScribeTool for QueryLorebookTool {
    fn name(&self) -> &'static str {
        "query_lorebook"
    }
    
    fn description(&self) -> &'static str {
        "Search lorebook entries by name, category, tags, or full-text search. \
         Provides access to world knowledge, character information, and lore."
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
                                "type": { "const": "ByName" },
                                "name": { 
                                    "type": "string", 
                                    "description": "Name/title to search for (partial match)" 
                                }
                            },
                            "required": ["type", "name"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByCategory" },
                                "category": { 
                                    "type": "string", 
                                    "description": "Category/lorebook name to search in" 
                                }
                            },
                            "required": ["type", "category"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "ByTags" },
                                "tags": { 
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Tags to search for" 
                                }
                            },
                            "required": ["type", "tags"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "FullText" },
                                "query": { 
                                    "type": "string", 
                                    "description": "Text to search in titles and content" 
                                }
                            },
                            "required": ["type", "query"]
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
            "required": ["user_id", "query"]
        })
    }
    
    #[instrument(skip(self, params), fields(tool = "query_lorebook"))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        let input: QueryLorebookInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;
        
        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        let limit = input.limit.unwrap_or(10).min(100);
        
        info!("Querying lorebook for user {} with query: {:?}", user_id, input.query);
        
        // Get user's DEK for decryption
        let user_dek = self.encryption_service
            .get_user_dek(user_id)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get user DEK: {}", e)))?
            .ok_or_else(|| ToolError::ExecutionFailed("User DEK not found".to_string()))?;
        
        let query_type = match &input.query {
            LorebookQuery::ByName { .. } => "ByName",
            LorebookQuery::ByCategory { .. } => "ByCategory",
            LorebookQuery::ByTags { .. } => "ByTags",
            LorebookQuery::FullText { .. } => "FullText",
        };
        
        let mut entries = self.search_entries(user_id, &input.query, &user_dek).await?;
        let total_found = entries.len();
        
        // Apply limit
        entries.truncate(limit);
        
        let output = QueryLorebookOutput {
            entries,
            total_found,
            query_type: query_type.to_string(),
        };
        
        Ok(ToolResult::Success(serde_json::to_value(output)?))
    }
}

/// Tool for creating and updating lorebook entries
#[derive(Clone)]
pub struct ManageLorebookTool {
    lorebook_service: Arc<LorebookService>,
    encryption_service: Arc<EncryptionService>,
    db_pool: PgPool,
}

impl ManageLorebookTool {
    pub fn new(
        lorebook_service: Arc<LorebookService>,
        encryption_service: Arc<EncryptionService>,
        db_pool: PgPool,
    ) -> Self {
        Self {
            lorebook_service,
            encryption_service,
            db_pool,
        }
    }
}

/// Input for managing lorebook entries
#[derive(Debug, Deserialize)]
pub struct ManageLorebookInput {
    /// User ID performing the operation
    pub user_id: String,
    /// The operation to perform
    pub operation: LorebookOperation,
}

/// Lorebook management operations
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum LorebookOperation {
    /// Create a new lorebook entry
    Create {
        name: String,
        category: String,
        content: String,
        tags: Vec<String>,
        lorebook_id: Option<String>,
    },
    /// Update an existing entry
    Update {
        entry_id: String,
        updates: LorebookUpdateFields,
    },
    /// Link an entry to an entity
    LinkToEntity {
        entry_id: String,
        entity_id: String,
    },
}

/// Fields that can be updated
#[derive(Debug, Deserialize)]
pub struct LorebookUpdateFields {
    pub name: Option<String>,
    pub content: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Output from manage lorebook operations
#[derive(Debug, Serialize)]
pub struct ManageLorebookOutput {
    pub operation: String,
    pub success: bool,
    pub entry_id: Option<Uuid>,
    pub message: String,
}

#[async_trait]
impl ScribeTool for ManageLorebookTool {
    fn name(&self) -> &'static str {
        "manage_lorebook"
    }
    
    fn description(&self) -> &'static str {
        "Create, update, or link lorebook entries. Use this to record new world knowledge, \
         update existing lore, or associate entries with entities."
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
                                "type": { "const": "Create" },
                                "name": { "type": "string", "description": "Entry title" },
                                "category": { "type": "string", "description": "Category/type of entry" },
                                "content": { "type": "string", "description": "Entry content" },
                                "tags": { 
                                    "type": "array",
                                    "items": { "type": "string" },
                                    "description": "Tags for categorization"
                                },
                                "lorebook_id": { 
                                    "type": "string", 
                                    "description": "Optional specific lorebook ID" 
                                }
                            },
                            "required": ["type", "name", "category", "content", "tags"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "Update" },
                                "entry_id": { "type": "string", "description": "Entry ID to update" },
                                "updates": {
                                    "type": "object",
                                    "properties": {
                                        "name": { "type": "string" },
                                        "content": { "type": "string" },
                                        "tags": { 
                                            "type": "array",
                                            "items": { "type": "string" }
                                        }
                                    }
                                }
                            },
                            "required": ["type", "entry_id", "updates"]
                        },
                        {
                            "type": "object",
                            "properties": {
                                "type": { "const": "LinkToEntity" },
                                "entry_id": { "type": "string", "description": "Lorebook entry ID" },
                                "entity_id": { "type": "string", "description": "Entity ID to link to" }
                            },
                            "required": ["type", "entry_id", "entity_id"]
                        }
                    ]
                }
            },
            "required": ["user_id", "operation"]
        })
    }
    
    #[instrument(skip(self, params), fields(tool = "manage_lorebook"))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        let input: ManageLorebookInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;
        
        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        info!("Managing lorebook for user {} with operation: {:?}", user_id, input.operation);
        
        // Get user's DEK for encryption
        let user_dek = self.encryption_service
            .get_user_dek(user_id)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get user DEK: {}", e)))?
            .ok_or_else(|| ToolError::ExecutionFailed("User DEK not found".to_string()))?;
        
        match input.operation {
            LorebookOperation::Create { name, category, content, tags: _, lorebook_id } => {
                // Parse lorebook ID if provided
                let lb_id = if let Some(id_str) = lorebook_id {
                    Some(Uuid::parse_str(&id_str)
                        .map_err(|e| ToolError::InvalidParams(format!("Invalid lorebook_id: {}", e)))?)
                } else {
                    None
                };
                
                // Use the service method designed for narrative intelligence
                let entry_id = self.lorebook_service
                    .create_entry_for_narrative_intelligence(
                        user_id,
                        lb_id,
                        &user_dek,
                        name.clone(),
                        content.clone(),
                        serde_json::json!({
                            "category": category,
                            "source": "orchestrator_tool"
                        }),
                    )
                    .await
                    .map_err(|e| ToolError::ExecutionFailed(format!("Failed to create entry: {}", e)))?;
                
                Ok(ToolResult::Success(serde_json::to_value(ManageLorebookOutput {
                    operation: "create".to_string(),
                    success: true,
                    entry_id: Some(entry_id),
                    message: format!("Created lorebook entry '{}'", name),
                })?))
            },
            
            LorebookOperation::Update { entry_id, updates } => {
                // TODO: Implement update functionality
                // This would require adding an update method to LorebookService that accepts user_id directly
                warn!("Update operation not yet implemented");
                
                Ok(ToolResult::Success(serde_json::to_value(ManageLorebookOutput {
                    operation: "update".to_string(),
                    success: false,
                    entry_id: None,
                    message: "Update operation not yet implemented".to_string(),
                })?))
            },
            
            LorebookOperation::LinkToEntity { entry_id, entity_id } => {
                // TODO: Implement entity linking
                // This would require a new table/relationship in the database
                warn!("LinkToEntity operation not yet implemented");
                
                Ok(ToolResult::Success(serde_json::to_value(ManageLorebookOutput {
                    operation: "link_to_entity".to_string(),
                    success: false,
                    entry_id: None,
                    message: "Entity linking not yet implemented".to_string(),
                })?))
            },
        }
    }
}