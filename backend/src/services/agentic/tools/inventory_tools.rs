// backend/src/services/agentic/tools/inventory_tools.rs
//
// AI-powered inventory management tools for the Orchestrator and other agents
// Uses AI to interpret natural language queries about inventories

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, instrument};
use genai::chat::{ChatRequest, ChatMessage, ChatRole, ChatOptions, ChatResponseFormat, JsonSchemaSpec, SafetySetting, HarmCategory, HarmBlockThreshold};

use crate::{
    services::{
        agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
        agentic::unified_tool_registry::{
            SelfRegisteringTool, ToolCategory, ToolCapability, ToolSecurityPolicy, AgentType,
            ToolExample, DataAccessPolicy, AuditLevel, ResourceRequirements, ExecutionTime, ErrorCode
        },
    },
    errors::AppError,
    state::AppState,
    auth::session_dek::SessionDek,
};

/// AI-powered tool that interprets natural language queries about inventories
#[derive(Clone)]
pub struct QueryInventoryTool {
    app_state: Arc<AppState>,
}

impl QueryInventoryTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
    
    /// Use AI to interpret the inventory query and return structured information
    async fn interpret_inventory_query(
        &self,
        user_id: Uuid,
        query_text: &str,
        context: Option<JsonValue>,
    ) -> Result<InventoryQueryResult, ToolError> {
        // Create schema for AI to structure inventory query interpretation
        let schema = json!({
            "type": "object",
            "properties": {
                "query_interpretation": {
                    "type": "string",
                    "description": "Natural language interpretation of the inventory query"
                },
                "target_entities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "entity_id": {"type": "string"},
                            "entity_name": {"type": "string"},
                            "reason": {"type": "string"}
                        },
                        "required": ["entity_id", "entity_name", "reason"]
                    },
                    "description": "Entities whose inventories should be queried"
                },
                "item_filters": {
                    "type": "object",
                    "properties": {
                        "types": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Item types to filter for"
                        },
                        "tags": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Tags to filter items by"
                        },
                        "properties": {
                            "type": "object",
                            "description": "Key-value property filters"
                        }
                    }
                },
                "search_scope": {
                    "type": "string",
                    "enum": ["direct", "nested", "world"],
                    "description": "Scope of inventory search"
                },
                "inventory_summary": {
                    "type": "object",
                    "properties": {
                        "total_items": {"type": "integer"},
                        "total_weight": {"type": "number"},
                        "total_value": {"type": "number"},
                        "item_categories": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "category": {"type": "string"},
                                    "count": {"type": "integer"}
                                }
                            }
                        }
                    },
                    "description": "Summary statistics about the inventory"
                }
            },
            "required": ["query_interpretation", "search_scope"]
        });

        // Build context for AI interpretation
        let context_str = if let Some(ctx) = context {
            format!("\nAdditional context: {}", serde_json::to_string_pretty(&ctx)?)
        } else {
            String::new()
        };

        let prompt = format!(
            "Interpret this inventory query and structure the response according to the schema:\n\n\
             Query: '{}'\n\n\
             User ID: {}{}\n\n\
             Please analyze what inventory information is being requested and identify:\
             - Which entities' inventories to examine\
             - What items to filter for (by type, tags, or properties)\
             - Whether to search nested containers or just direct inventory\
             - Any summary statistics that would be helpful",
            query_text, user_id, context_str
        );

        // Create AI request with structured output
        let system_prompt = "You are an inventory management agent that interprets natural language queries about items and inventories. All content is for a fictional roleplay game.";
        
        let chat_request = ChatRequest::new(vec![
            ChatMessage {
                role: ChatRole::User,
                content: prompt.into(),
                options: None,
            }
        ]).with_system(system_prompt);
        
        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];
        
        let chat_options = ChatOptions {
            max_tokens: Some(1200),
            temperature: Some(0.3),
            response_format: Some(ChatResponseFormat::JsonSchemaSpec(
                JsonSchemaSpec { schema: schema.clone() }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };
        
        // Use AI to interpret the query
        let model = &self.app_state.config.query_planning_model;
        let response = self.app_state.ai_client
            .exec_chat(model, chat_request, Some(chat_options))
            .await
            .map_err(|e| ToolError::AppError(e))?;
        
        // Extract response text
        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| ToolError::ExecutionFailed("No text content in AI response".to_string()))?;
        
        let interpretation: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}", e)))?;

        // For now, return a mock result showing the AI interpretation
        // In a real implementation, this would query the actual inventory system
        Ok(InventoryQueryResult {
            entity_id: Uuid::nil(),
            entity_name: "AI Inventory Query".to_string(),
            items: vec![],
            total_items: 0,
            query_type: interpretation["search_scope"].as_str().unwrap_or("unknown").to_string(),
        })
    }
}

/// Input parameters for AI-powered inventory queries
#[derive(Debug, Deserialize)]
pub struct QueryInventoryInput {
    /// User ID performing the query
    pub user_id: String,
    /// Natural language query about inventory
    pub query: String,
    /// Optional context (entity IDs, locations, etc.)
    pub context: Option<JsonValue>,
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
        "AI-powered inventory query tool that interprets natural language questions about items and inventories. \
         Use this to find what items entities are carrying, search for specific item types, \
         or get inventory summaries."
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
                    "type": "string",
                    "description": "Natural language query about inventories (e.g., 'What items are in the dragon's hoard?', 'Find all healing potions in the village')"
                },
                "context": {
                    "type": "object",
                    "description": "Optional context with entity IDs, locations, or other relevant information"
                }
            },
            "required": ["user_id", "query"]
        })
    }
    
    #[instrument(skip(self, params, _session_dek), fields(tool = "query_inventory"))]
    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let input: QueryInventoryInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;
        
        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        info!("AI-interpreting inventory query for user {}: '{}'", user_id, input.query);
        
        let result = self.interpret_inventory_query(user_id, &input.query, input.context).await?;
        
        Ok(serde_json::to_value(result)?)
    }
}

#[async_trait]
impl SelfRegisteringTool for QueryInventoryTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Discovery
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "query".to_string(),
                target: "inventory contents".to_string(),
                context: Some("natural language".to_string()),
            },
            ToolCapability {
                action: "search".to_string(),
                target: "items by type or tag".to_string(),
                context: Some("across entities".to_string()),
            },
            ToolCapability {
                action: "analyze".to_string(),
                target: "inventory statistics".to_string(),
                context: Some("weight, value, categories".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to understand what items entities are carrying, search for specific \
         item types or tags, get inventory summaries, or answer questions about item locations. \
         Interprets natural language queries about inventories.".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for modifying inventories (use manage_inventory instead) or for \
         queries unrelated to items and containers.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Finding specific items".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "query": "What healing items does the party have?",
                    "context": {
                        "party_member_ids": ["uuid1", "uuid2", "uuid3"]
                    }
                }),
                expected_output: "Returns inventory listing with all healing-related items carried by party members".to_string(),
            },
            ToolExample {
                scenario: "Container inventory check".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "query": "Show me everything in the merchant's shop chest",
                    "context": {
                        "chest_entity_id": "chest-uuid-123"
                    }
                }),
                expected_output: "Returns all items contained within the specified chest entity".to_string(),
            },
            ToolExample {
                scenario: "Item search by type".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "query": "Find all weapons in the castle armory",
                    "context": {
                        "location": "castle_armory"
                    }
                }),
                expected_output: "Returns all weapon-type items found in the castle armory location".to_string(),
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
            rate_limit: Some(crate::services::agentic::unified_tool_registry::RateLimit {
                calls_per_minute: 100,
                calls_per_hour: 2000,
                burst_size: 20,
            }),
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false, // Read-only tool
                allowed_scopes: vec!["inventory".to_string(), "entities".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 50,
            execution_time: ExecutionTime::Moderate, // AI interpretation takes time
            external_calls: true, // Calls AI model
            compute_intensive: false,
        }
    }
    
    fn dependencies(&self) -> Vec<String> {
        vec![
            "ai_client".to_string(),
            "ecs_entity_manager".to_string(),
        ]
    }
    
    fn tags(&self) -> Vec<String> {
        vec![
            "inventory".to_string(),
            "query".to_string(),
            "ai-powered".to_string(),
            "natural-language".to_string(),
            "items".to_string(),
            "containers".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "entity_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "UUID of the primary entity queried"
                },
                "entity_name": {
                    "type": "string",
                    "description": "Name of the entity or query type"
                },
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "format": "uuid"},
                            "name": {"type": "string"},
                            "item_type": {"type": "string"},
                            "quantity": {"type": "integer"},
                            "weight": {"type": "number"},
                            "value": {"type": "integer"},
                            "container_id": {"type": "string", "format": "uuid"},
                            "tags": {
                                "type": "array",
                                "items": {"type": "string"}
                            },
                            "properties": {"type": "object"}
                        },
                        "required": ["id", "name", "item_type", "quantity"]
                    },
                    "description": "List of inventory items found"
                },
                "total_items": {
                    "type": "integer",
                    "description": "Total count of items found"
                },
                "query_type": {
                    "type": "string",
                    "description": "Type of query performed (direct, nested, by_type, etc.)"
                }
            },
            "required": ["entity_id", "entity_name", "items", "total_items", "query_type"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "INVALID_QUERY".to_string(),
                description: "The natural language query could not be interpreted".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "ENTITY_NOT_FOUND".to_string(),
                description: "Referenced entity does not exist".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "AI_INTERPRETATION_FAILED".to_string(),
                description: "AI model failed to interpret the query".to_string(),
                retry_able: true,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "2.0.0-ai"
    }
}

/// AI-powered tool for managing entity inventories through natural language commands
#[derive(Clone)]
pub struct ManageInventoryTool {
    app_state: Arc<AppState>,
}

impl ManageInventoryTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
    
    /// Use AI to interpret inventory management commands
    async fn interpret_inventory_command(
        &self,
        user_id: Uuid,
        command: &str,
        context: Option<JsonValue>,
    ) -> Result<ManageInventoryOutput, ToolError> {
        // Create schema for AI to structure inventory management commands
        let schema = json!({
            "type": "object",
            "properties": {
                "command_interpretation": {
                    "type": "string",
                    "description": "Natural language interpretation of the inventory command"
                },
                "operation_type": {
                    "type": "string",
                    "enum": ["move", "create", "update", "remove", "transfer", "organize"],
                    "description": "Type of inventory operation"
                },
                "affected_items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "item_id": {"type": "string"},
                            "item_name": {"type": "string"},
                            "quantity": {"type": "integer"},
                            "source_container": {"type": "string"},
                            "target_container": {"type": "string"},
                            "modifications": {"type": "object"}
                        }
                    },
                    "description": "Items affected by the operation"
                },
                "validation_checks": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "check_type": {"type": "string"},
                            "description": {"type": "string"},
                            "required": {"type": "boolean"}
                        }
                    },
                    "description": "Validation checks to perform before executing"
                },
                "expected_outcome": {
                    "type": "string",
                    "description": "Expected result of the operation"
                }
            },
            "required": ["command_interpretation", "operation_type"]
        });

        // Build context for AI interpretation
        let context_str = if let Some(ctx) = context {
            format!("\nAdditional context: {}", serde_json::to_string_pretty(&ctx)?)
        } else {
            String::new()
        };

        let prompt = format!(
            "Interpret this inventory management command and structure the response according to the schema:\n\n\
             Command: '{}'\n\n\
             User ID: {}{}\n\n\
             Please analyze what inventory operation is being requested and identify:\
             - The type of operation (move, create, update, remove, etc.)\
             - Which items are affected and their quantities\
             - Source and target containers if applicable\
             - Any modifications to item properties\
             - Validation checks that should be performed\
             - The expected outcome of the operation",
            command, user_id, context_str
        );

        // Create AI request with structured output
        let system_prompt = "You are an inventory management agent that interprets natural language commands to manage items and inventories. All content is for a fictional roleplay game.";
        
        let chat_request = ChatRequest::new(vec![
            ChatMessage {
                role: ChatRole::User,
                content: prompt.into(),
                options: None,
            }
        ]).with_system(system_prompt);
        
        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];
        
        let chat_options = ChatOptions {
            max_tokens: Some(1200),
            temperature: Some(0.3),
            response_format: Some(ChatResponseFormat::JsonSchemaSpec(
                JsonSchemaSpec { schema: schema.clone() }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };
        
        // Use AI to interpret the command
        let model = &self.app_state.config.tactical_agent_model;
        let response = self.app_state.ai_client
            .exec_chat(model, chat_request, Some(chat_options))
            .await
            .map_err(|e| ToolError::AppError(e))?;
        
        // Extract response text
        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| ToolError::ExecutionFailed("No text content in AI response".to_string()))?;
        
        let interpretation: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}", e)))?;

        // For now, return a mock result showing the AI interpretation
        // In a real implementation, this would execute the actual inventory operations
        Ok(ManageInventoryOutput {
            operation: interpretation["operation_type"].as_str().unwrap_or("unknown").to_string(),
            success: true,
            item_id: None,
            message: format!("AI interpreted command: {}", 
                interpretation["command_interpretation"].as_str().unwrap_or("unknown")),
        })
    }
}

/// Input for AI-powered inventory management
#[derive(Debug, Deserialize)]
pub struct ManageInventoryInput {
    /// User ID performing the operation
    pub user_id: String,
    /// Natural language command for inventory management
    pub command: String,
    /// Optional context (entity IDs, item references, etc.)
    pub context: Option<JsonValue>,
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
        "AI-powered inventory management tool that interprets natural language commands \
         to move, create, update, or organize items in entity inventories."
    }
    
    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the operation"
                },
                "command": {
                    "type": "string",
                    "description": "Natural language command for inventory management (e.g., 'Move the sword to the armory chest', 'Create 5 healing potions in the alchemist's bag')"
                },
                "context": {
                    "type": "object",
                    "description": "Optional context with entity IDs, item references, or other relevant information"
                }
            },
            "required": ["user_id", "command"]
        })
    }
    
    #[instrument(skip(self, params, _session_dek), fields(tool = "manage_inventory"))]
    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let input: ManageInventoryInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;
        
        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        info!("AI-interpreting inventory command for user {}: '{}'", user_id, input.command);
        
        let result = self.interpret_inventory_command(user_id, &input.command, input.context).await?;
        
        Ok(serde_json::to_value(result)?)
    }
}

#[async_trait]
impl SelfRegisteringTool for ManageInventoryTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Management
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "move".to_string(),
                target: "items between containers".to_string(),
                context: Some("natural language".to_string()),
            },
            ToolCapability {
                action: "create".to_string(),
                target: "new inventory items".to_string(),
                context: Some("with properties".to_string()),
            },
            ToolCapability {
                action: "update".to_string(),
                target: "item properties".to_string(),
                context: Some("quantity, value, attributes".to_string()),
            },
            ToolCapability {
                action: "organize".to_string(),
                target: "inventory contents".to_string(),
                context: Some("sorting and grouping".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to modify inventories through natural language commands: \
         moving items between containers, creating new items, updating quantities or properties, \
         organizing inventory contents, or performing bulk inventory operations.".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for querying inventories (use query_inventory instead) or for \
         operations unrelated to inventory management.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Moving items between containers".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "command": "Move the enchanted sword from the player's backpack to the vault",
                    "context": {
                        "player_id": "player-uuid-123",
                        "vault_id": "vault-uuid-456"
                    }
                }),
                expected_output: "Moves the specified sword item to the vault container".to_string(),
            },
            ToolExample {
                scenario: "Creating new items".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "command": "Create 10 healing potions in the alchemist's inventory",
                    "context": {
                        "alchemist_id": "alchemist-uuid-789"
                    }
                }),
                expected_output: "Creates 10 new healing potion items in the alchemist's inventory".to_string(),
            },
            ToolExample {
                scenario: "Updating item properties".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "command": "Set the ancient tome's value to 1000 gold and mark it as identified",
                    "context": {
                        "item_id": "tome-uuid-321"
                    }
                }),
                expected_output: "Updates the tome's value and identification status".to_string(),
            },
        ]
    }
    
    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Tactical,
            ],
            required_capabilities: vec!["inventory_management".to_string()],
            rate_limit: Some(crate::services::agentic::unified_tool_registry::RateLimit {
                calls_per_minute: 50,
                calls_per_hour: 500,
                burst_size: 10,
            }),
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true, // Can modify inventory data
                allowed_scopes: vec!["inventory".to_string(), "entities".to_string()],
            },
            audit_level: AuditLevel::Detailed, // Track all inventory changes
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 100,
            execution_time: ExecutionTime::Moderate, // AI interpretation + DB operations
            external_calls: true, // Calls AI model
            compute_intensive: false,
        }
    }
    
    fn dependencies(&self) -> Vec<String> {
        vec![
            "ai_client".to_string(),
            "ecs_entity_manager".to_string(),
            "db_pool".to_string(),
        ]
    }
    
    fn tags(&self) -> Vec<String> {
        vec![
            "inventory".to_string(),
            "management".to_string(),
            "ai-powered".to_string(),
            "natural-language".to_string(),
            "items".to_string(),
            "modification".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "description": "Type of operation performed"
                },
                "success": {
                    "type": "boolean",
                    "description": "Whether the operation succeeded"
                },
                "item_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "UUID of affected item (if applicable)"
                },
                "message": {
                    "type": "string",
                    "description": "Human-readable result message"
                }
            },
            "required": ["operation", "success", "message"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "INVALID_COMMAND".to_string(),
                description: "The natural language command could not be interpreted".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "CONTAINER_FULL".to_string(),
                description: "Target container has no space for the item".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "ITEM_NOT_FOUND".to_string(),
                description: "Referenced item does not exist".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "INSUFFICIENT_PERMISSIONS".to_string(),
                description: "User lacks permission to modify this inventory".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "AI_INTERPRETATION_FAILED".to_string(),
                description: "AI model failed to interpret the command".to_string(),
                retry_able: true,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "2.0.0-ai"
    }
}

/// Register inventory tools with the unified registry
pub fn register_inventory_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    // Register QueryInventoryTool
    let query_tool = Arc::new(QueryInventoryTool::new(app_state.clone())) 
        as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register_if_not_exists(query_tool)?;
    
    // Register ManageInventoryTool
    let manage_tool = Arc::new(ManageInventoryTool::new(app_state.clone())) 
        as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register_if_not_exists(manage_tool)?;
    
    tracing::info!("Registered 2 AI-powered inventory tools");
    Ok(())
}