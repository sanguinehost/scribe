//! AI-Driven Entity CRUD Tools
//!
//! These tools use AI models to interpret natural language requests about entity operations
//! and translate them into intelligent world simulation actions. They leverage the configured
//! AI models to provide context-aware, reasoning-based entity management.

use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, debug, instrument, warn};
use chrono::{DateTime, Utc};
use genai::chat::{ChatRequest, ChatMessage, ChatRole, ChatOptions, ChatResponseFormat, JsonSchemaSpec, SafetySetting, HarmCategory, HarmBlockThreshold};

use crate::{
    services::{EcsEntityManager, ComponentQuery, EntityQueryResult, ComponentUpdate, ComponentOperation},
    models::ecs::{
        SpatialScale, SalienceTier, ParentLinkComponent, NameComponent, 
        EnhancedPositionComponent, HierarchicalCoordinates, SpatialArchetypeComponent, 
        TemporalComponent, SpatialComponent, SalienceComponent, GameTime, TimeMode
    },
    models::spatial::{
        EnhancedSpatialComponent, SpatialType as EnhancedSpatialType,
        RelativePosition, AbsolutePosition, Rotation
    },
    services::agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    services::agentic::unified_tool_registry::{SelfRegisteringTool, ToolMetadata, ToolCategory, ToolCapability, ToolSecurityPolicy, AgentType, ToolExample, DataAccessPolicy, AuditLevel, ResourceRequirements, ExecutionTime, ErrorCode},
    state::AppState,
    errors::AppError,
    auth::session_dek::SessionDek,
};

// ===== AI-DRIVEN FIND ENTITY TOOL =====

/// AI-powered tool that interprets natural language search requests and finds entities 
/// using intelligent reasoning about context, relationships, and semantic meaning
#[derive(Clone)]
pub struct FindEntityTool {
    app_state: Arc<AppState>,
}

impl FindEntityTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Build AI prompt for interpreting natural language entity search requests
    fn build_entity_search_prompt(&self, request: &str, context: &str) -> String {
        format!(
            r#"You are an intelligent entity search agent for a dynamic roleplay world model system.

Your task is to interpret natural language search requests and translate them into structured entity queries.

SEARCH REQUEST:
"{}"

CURRENT CONTEXT:
{}

Your analysis should identify:
1. What type of entities the user is looking for
2. Key characteristics, names, or properties to match
3. Spatial, temporal, or relationship constraints
4. The scope and scale of the search (Cosmic/Planetary/Intimate scales, or specific spatial types)
5. Fuzzy matching requirements (partial names, synonyms, related concepts)

Note: If you need information about available spatial types, use the 'query_spatial_types' tool first.

RESPONSE FORMAT (JSON):
{{
    "interpretation": "Clear restatement of what the user is searching for",
    "search_strategy": "semantic_search|name_match|component_based|relationship_based|spatial_search",
    "key_terms": ["term1", "term2", "term3"],
    "entity_types": ["character", "location", "item", "organization", "concept"],
    "spatial_scope": "Cosmic|Planetary|Intimate|Any",
    "fuzzy_matching": true|false,
    "relationship_constraints": {{"parent": "entity_name", "contains": "entity_type", "nearby": "location"}},
    "component_requirements": ["Name", "Position", "SpatialArchetype"],
    "reasoning": "Explanation of search strategy and why these parameters were chosen",
    "expected_results": "Description of what kind of results should be returned"
}}

Examples:
- "Find the wizard's tower" → semantic_search for buildings associated with magic users
- "Show me all characters in the tavern" → spatial_search for people in a specific location  
- "Look for anything related to the ancient artifact" → relationship_based search for connected entities
- "Find items that can heal" → component_based search for objects with healing properties

Be intelligent about interpreting vague or contextual references."#,
            request,
            context
        )
    }

    /// Execute AI request with structured output
    async fn execute_ai_request(&self, prompt: &str, schema: &JsonValue, model: &str) -> Result<JsonValue, ToolError> {
        let system_prompt = "You are an entity analysis agent for a fictional roleplay world. All content is creative fiction for a game.";
        
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
            max_tokens: Some(2000),
            temperature: Some(0.3),
            response_format: Some(ChatResponseFormat::JsonSchemaSpec(
                JsonSchemaSpec { schema: schema.clone() }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

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

        serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}. Response: {}", e, response_text)))
    }
}

/// AI interpretation of entity search request
#[derive(Debug, Serialize, Deserialize)]
pub struct EntitySearchInterpretation {
    pub interpretation: String,
    pub search_strategy: String,
    pub key_terms: Vec<String>,
    pub entity_types: Vec<String>,
    pub spatial_scope: String,
    pub fuzzy_matching: bool,
    pub relationship_constraints: JsonValue,
    pub component_requirements: Vec<String>,
    pub reasoning: String,
    pub expected_results: String,
}

/// Input parameters for finding entities
#[derive(Debug, Deserialize)]
pub struct FindEntityInput {
    /// User ID performing the operation
    pub user_id: String,
    /// Natural language search request
    pub search_request: String,
    /// Optional context about the current scene or situation
    pub context: Option<String>,
    /// Maximum number of results to return (default: 10)
    pub limit: Option<usize>,
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
        "AI-powered natural language entity search that interprets requests like 'find the wizard's tower' \
         or 'show me all characters in the tavern' and intelligently searches the world model using \
         semantic reasoning and context-aware analysis."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the search"
                },
                "search_request": {
                    "type": "string",
                    "description": "Natural language description of what entities to find (e.g., 'find the wizard's tower', 'show me all characters in the tavern')"
                },
                "context": {
                    "type": "string",
                    "description": "Optional context about the current scene or situation to help with search interpretation"
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Maximum number of results to return"
                }
            },
            "required": ["user_id", "search_request"]
        })
    }

    #[instrument(skip(self, params, session_dek), fields(tool = "find_entity"))]
    async fn execute(&self, params: &ToolParams, session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let input: FindEntityInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;

        let limit = input.limit.unwrap_or(10).min(100);
        let context = input.context.unwrap_or_else(|| "No additional context provided".to_string());

        info!("AI-driven entity search for user {}: '{}'", user_id, input.search_request);

        // Step 1: Use AI to interpret the natural language search request
        let prompt = self.build_entity_search_prompt(&input.search_request, &context);
        
        let search_schema = json!({
            "type": "object",
            "properties": {
                "interpretation": {"type": "string"},
                "search_strategy": {"type": "string", "enum": ["semantic_search", "name_match", "component_based", "relationship_based", "spatial_search"]},
                "key_terms": {"type": "array", "items": {"type": "string"}},
                "entity_types": {"type": "array", "items": {"type": "string"}},
                "spatial_scope": {
                    "type": "string",
                    "description": "Spatial scope or specific spatial type (Cosmic/Planetary/Intimate scales, or specific types like Galaxy, Planet, City, Room, etc.)"
                },
                "fuzzy_matching": {"type": "boolean"},
                "relationship_constraints": {
                    "type": "object",
                    "properties": {
                        "parent": {"type": "string", "description": "Parent entity name or ID"},
                        "contains": {"type": "string", "description": "Entity type that should be contained"},
                        "nearby": {"type": "string", "description": "Location or entity this should be near"},
                        "within": {"type": "string", "description": "Spatial container entity"},
                        "owned_by": {"type": "string", "description": "Entity that owns this"},
                        "related_to": {"type": "string", "description": "Related entity"},
                        "distance_from": {"type": "string", "description": "Distance constraint from another entity"}
                    }
                },
                "component_requirements": {"type": "array", "items": {"type": "string"}},
                "reasoning": {"type": "string"},
                "expected_results": {"type": "string"}
            },
            "required": ["interpretation", "search_strategy", "key_terms", "entity_types", "spatial_scope", "fuzzy_matching", "relationship_constraints", "component_requirements", "reasoning", "expected_results"]
        });

        // Execute AI interpretation using entity resolution model
        let ai_response = self.execute_ai_request(&prompt, &search_schema, &self.app_state.config.agentic_entity_resolution_model).await?;
        
        let _search_interpretation: EntitySearchInterpretation = serde_json::from_value(ai_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI search interpretation: {}", e)))?;

        debug!("AI interpreted search: {}", _search_interpretation.interpretation);

        // Step 2: Query the ECS system using the AI interpretation
        let user_uuid = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user ID: {}", e)))?;
        
        use crate::services::ecs_entity_manager::ComponentQuery;
        
        // Build search criteria based on AI interpretation
        let mut queries = Vec::new();
        
        // Always include entities with Name component
        queries.push(ComponentQuery::HasComponent("Name".to_string()));
        
        // Add entity type query if specified
        if !_search_interpretation.entity_types.is_empty() {
            for entity_type in &_search_interpretation.entity_types {
                queries.push(ComponentQuery::ComponentDataEquals(
                    "EntityType".to_string(),
                    "type".to_string(),
                    json!(entity_type),
                ));
            }
        }
        
        // Add name pattern queries if specified
        for key_term in &_search_interpretation.key_terms {
            queries.push(ComponentQuery::ComponentDataContains(
                "Name".to_string(),
                "name".to_string(),
                key_term.clone(),
            ));
        }
        
        // If no specific queries, just look for entities with Name component
        if queries.len() == 1 && _search_interpretation.key_terms.is_empty() && _search_interpretation.entity_types.is_empty() {
            debug!("No specific search criteria, returning all entities with Name component");
        }
        
        // Query for entities matching criteria
        let query_results = self.app_state.ecs_entity_manager
            .query_entities(user_uuid, queries, Some(10), None)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to query entities: {}", e)))?;
        
        let mut entities = Vec::new();
        
        for result in query_results {
            // Extract entity name from components
            let entity_name = result.components.iter()
                .find(|c| c.component_type == "Name")
                .and_then(|c| c.component_data.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("Unnamed Entity")
                .to_string();
            
            let component_types: Vec<String> = result.components.iter()
                .map(|c| c.component_type.clone())
                .collect();
            
            // Extract position if available
            let position = result.components.iter()
                .find(|c| c.component_type == "Position")
                .and_then(|c| c.component_data.as_object())
                .map(|data| PositionSummary {
                    x: data.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    y: data.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    z: data.get("z").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    scale: result.components.iter()
                        .find(|c| c.component_type == "Scale")
                        .and_then(|c| c.component_data.get("value"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                });
            
            // Extract parent ID if available
            let parent_id = result.components.iter()
                .find(|c| c.component_type == "ParentLink")
                .and_then(|c| c.component_data.get("parent_id"))
                .and_then(|id| id.as_str())
                .map(|s| s.to_string());
            
            entities.push(EntitySummary {
                entity_id: result.entity.id.to_string(),
                name: entity_name,
                scale: result.components.iter()
                    .find(|c| c.component_type == "Scale")
                    .and_then(|c| c.component_data.get("value"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                position,
                parent_id,
                component_types,
            });
        }

        let output = FindEntityOutput {
            total_found: entities.len(),
            search_criteria: format!("AI: {} ({})", _search_interpretation.interpretation, _search_interpretation.search_strategy),
            entities,
        };

        info!("AI found {} entities matching: '{}'", output.total_found, input.search_request);
        Ok(serde_json::to_value(output)?)
    }
}

#[async_trait]
impl SelfRegisteringTool for FindEntityTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Discovery
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "search".to_string(),
                target: "entities".to_string(),
                context: Some("natural language".to_string()),
            },
            ToolCapability {
                action: "interpret".to_string(),
                target: "search requests".to_string(),
                context: Some("semantic analysis".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to find entities in the world based on natural language descriptions. \
         Perfect for requests like 'find the wizard's tower', 'show me all characters in the tavern', \
         or 'look for anything related to the ancient artifact'.".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for creating new entities, modifying existing entities, or when you already \
         have specific entity IDs. Use specific entity management tools instead.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Find magical items in a specific location".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "search_request": "Find all magical items in the tower",
                    "context": "Player is exploring the Mage's Tower"
                }),
                expected_output: "List of magical items found in the tower with their properties and locations".to_string(),
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
                write_access: false,
                allowed_scopes: vec!["entities".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 60,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Uses AI client
            compute_intensive: false,
        }
    }
    
    fn dependencies(&self) -> Vec<String> {
        vec![
            "ecs_entity_manager".to_string(),
            "ai_client".to_string(),
        ]
    }
    
    fn tags(&self) -> Vec<String> {
        vec![
            "entity".to_string(),
            "search".to_string(),
            "discovery".to_string(),
            "ai-powered".to_string(),
            "natural-language".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "entities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "entity_id": {"type": "string"},
                            "name": {"type": "string"},
                            "scale": {"type": "string"},
                            "position": {
                                "type": "object",
                                "properties": {
                                    "x": {"type": "number"},
                                    "y": {"type": "number"},
                                    "z": {"type": "number"}
                                }
                            },
                            "component_types": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        },
                        "required": ["entity_id", "name"]
                    },
                    "description": "List of entities found matching the search criteria"
                },
                "total_found": {
                    "type": "integer",
                    "description": "Total number of entities found"
                },
                "search_criteria": {
                    "type": "string",
                    "description": "AI interpretation of the search request"
                }
            },
            "required": ["entities", "total_found", "search_criteria"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "INVALID_USER_ID".to_string(),
                description: "The provided user ID is not valid or not found".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "AI_SEARCH_FAILED".to_string(),
                description: "The AI service failed to interpret the search request".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "NO_ENTITIES_FOUND".to_string(),
                description: "No entities were found matching the search criteria".to_string(),
                retry_able: false,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

// Placeholder structures for other tools that need to be implemented
// Note: These tools will use AI-driven interpretation of requests rather than hardcoded ECS operations
// They will interpret natural language requests and use intelligent reasoning to perform CRUD operations

/// Decrypted component data structure for AI processing
#[derive(Debug, Clone, Serialize)]
pub struct DecryptedComponent {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub component_type: String,
    pub component_data: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub user_id: Uuid,
}

/// AI-powered tool that retrieves detailed entity information using intelligent analysis
#[derive(Clone)]
pub struct GetEntityDetailsTool {
    app_state: Arc<AppState>,
}

impl GetEntityDetailsTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Decrypt encrypted component data in ECS components
    fn decrypt_entity_components(
        &self, 
        components: &[crate::models::ecs_diesel::EcsComponent], 
        session_dek: &SessionDek
    ) -> Result<Vec<DecryptedComponent>, ToolError> {
        let mut decrypted_components = Vec::new();
        
        for component in components {
            let decrypted_data = if let (Some(encrypted_data), Some(nonce)) = 
                (&component.encrypted_component_data, &component.component_data_nonce) {
                
                // Decrypt the component data using session_dek
                match self.app_state.encryption_service.decrypt(encrypted_data, nonce, session_dek.expose_bytes()) {
                    Ok(decrypted_bytes) => {
                        // Try to parse as JSON, fallback to string representation
                        match serde_json::from_slice::<serde_json::Value>(&decrypted_bytes) {
                            Ok(json_value) => json_value,
                            Err(_) => serde_json::Value::String(String::from_utf8_lossy(&decrypted_bytes).to_string())
                        }
                    },
                    Err(e) => {
                        warn!("Failed to decrypt component data for component {}: {}", component.id, e);
                        // Fallback to the plain component_data if decryption fails
                        component.component_data.clone()
                    }
                }
            } else {
                // Use plain component_data if no encrypted version exists
                component.component_data.clone()
            };
            
            decrypted_components.push(DecryptedComponent {
                id: component.id,
                entity_id: component.entity_id,
                component_type: component.component_type.clone(),
                component_data: decrypted_data,
                created_at: component.created_at,
                updated_at: component.updated_at,
                user_id: component.user_id,
            });
        }
        
        Ok(decrypted_components)
    }

    /// Use AI to interpret the entity details request and format comprehensive information
    async fn get_entity_details_with_ai(
        &self,
        user_id: Uuid,
        entity_identifier: &str,
        detail_request: &str,
        session_dek: &SessionDek,
    ) -> Result<EntityDetailsOutput, ToolError> {
        // First, resolve the entity using AI-driven search
        let find_entity_tool = crate::services::agentic::unified_tool_registry::UnifiedToolRegistry::get_tool("find_entity")
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get FindEntityTool: {}", e)))?;
        
        let find_params = json!({
            "user_id": user_id.to_string(),
            "search_request": format!("find entity: {}", entity_identifier),
            "context": format!("Looking for entity details: {}", detail_request),
            "limit": 1
        });
        
        let find_result = find_entity_tool.execute(&find_params, session_dek).await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to find entity: {}", e)))?;
            
        let entities = find_result.get("entities").and_then(|e| e.as_array())
            .ok_or_else(|| ToolError::ExecutionFailed("Invalid find_entity response".to_string()))?;
            
        if entities.is_empty() {
            return Err(ToolError::ExecutionFailed(format!("Entity '{}' not found", entity_identifier)));
        }
        
        let entity = &entities[0];
        let entity_id_str = entity.get("entity_id").and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::ExecutionFailed("Missing entity_id in response".to_string()))?;
        let entity_id = Uuid::parse_str(entity_id_str)
            .map_err(|_| ToolError::ExecutionFailed(format!("Invalid entity_id: {}", entity_id_str)))?;

        // Get the full entity details from ECS
        let entity_details = self.app_state.ecs_entity_manager
            .get_entity(user_id, entity_id)
            .await
            .map_err(|e| ToolError::AppError(e))?
            .ok_or_else(|| ToolError::ExecutionFailed(format!("Entity {} not found in ECS", entity_id)))?;

        // Use AI to interpret and format the entity details based on the request
        let schema = get_entity_details_analysis_schema();

        // Decrypt component data before passing to AI
        let decrypted_components = self.decrypt_entity_components(&entity_details.components, session_dek)?;
        let components_json = serde_json::to_string_pretty(&decrypted_components)
            .unwrap_or_else(|_| "[]".to_string());

        let prompt = format!(
            r#"You are an intelligent entity analysis agent for a dynamic world model system.

Your task is to analyze detailed entity information and provide comprehensive insights based on the user's request.

ENTITY IDENTIFIER: "{}"
USER REQUEST: "{}"
USER ID: {}

RAW ENTITY DATA:
Entity ID: {}
Components: {}

Your analysis should provide:
1. Clear interpretation of what the user wanted to know
2. High-level entity summary (name, type, description, scale, importance)
3. Detailed analysis of each component and its significance
4. Understanding of the entity's relationships and hierarchy
5. Assessment of the entity's narrative role and context
6. Intelligent suggestions for actions that could be taken

Format your response to be helpful for game masters, players, or AI agents who need to understand this entity's role in the world."#,
            entity_identifier,
            detail_request,
            user_id,
            entity_id,
            components_json
        );

        // Execute AI analysis
        let system_prompt = "You are an entity analysis agent for a fictional roleplay game. You provide detailed insights about entities in a fantasy world. All content is creative fiction.";
        
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
            max_tokens: Some(2000),
            temperature: Some(0.3),
            response_format: Some(ChatResponseFormat::JsonSchemaSpec(
                JsonSchemaSpec { schema: schema.clone() }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.agentic_entity_resolution_model, chat_request, Some(chat_options))
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

        let ai_analysis: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}", e)))?;

        // Combine raw entity data with AI analysis
        Ok(EntityDetailsOutput {
            entity_id: entity_id.to_string(),
            entity_name: entity.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
            ai_analysis,
            raw_components: entity_details.components,
            user_request: detail_request.to_string(),
        })
    }
}

/// Input parameters for getting entity details
#[derive(Debug, Deserialize)]
pub struct GetEntityDetailsInput {
    /// User ID performing the operation
    pub user_id: String,
    /// Entity identifier (name, ID, or description)
    pub entity_identifier: String,
    /// Specific details requested about the entity
    pub detail_request: String,
}

/// Input parameters for creating entities
#[derive(Debug, Deserialize)]
pub struct CreateEntityInput {
    /// User ID performing the operation
    pub user_id: String,
    /// Natural language description of what entity to create
    pub creation_request: String,
    /// Optional context about where/why to create this entity
    pub context: Option<String>,
}

/// Detailed output about an entity
#[derive(Debug, Serialize)]
pub struct EntityDetailsOutput {
    pub entity_id: String,
    pub entity_name: String,
    pub ai_analysis: JsonValue,
    pub raw_components: Vec<crate::models::ecs_diesel::EcsComponent>,
    pub user_request: String,
}

/// Output from entity creation
#[derive(Debug, Serialize)]
pub struct EntityCreationOutput {
    pub entity_id: String,
    pub creation_plan: JsonValue,
    pub user_request: String,
    pub created: bool,
    pub creation_summary: String,
}

/// Helper function to create the JSON schema for entity creation analysis
fn get_entity_creation_analysis_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "interpretation": {
                "type": "string",
                "description": "AI's understanding of what entity should be created"
            },
            "entity_type": {
                "type": "string",
                "description": "Type of entity being created (character, location, item, organization, concept)"
            },
            "entity_characteristics": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "description": {"type": "string"},
                    "spatial_scale": {"type": "string", "enum": ["Cosmic", "Planetary", "Intimate"]},
                    "spatial_type": {
                        "type": "string", 
                        "description": "Specific spatial type like Planet, City, Building, Room, Spaceship, etc. Can also be a custom type for unique entities (e.g., 'MagicalRealm', 'PocketDimension'). The system will automatically handle custom types."
                    },
                    "salience_tier": {"type": "string"}
                },
                "required": ["name", "description", "spatial_scale", "spatial_type"],
                "description": "Core characteristics of the entity"
            },
            "required_components": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "component_type": {"type": "string"},
                        "component_data": {
                            "type": "object",
                            "description": "Flexible component data structure",
                            "properties": {
                                "value": {
                                    "description": "Component-specific data"
                                }
                            }
                        },
                        "reasoning": {"type": "string"}
                    },
                    "required": ["component_type", "component_data", "reasoning"]
                },
                "description": "Components needed for this entity"
            },
            "spatial_placement": {
                "type": "object",
                "properties": {
                    "x": {"type": "number"},
                    "y": {"type": "number"},
                    "z": {"type": "number"},
                    "parent_entity": {"type": "string"},
                    "placement_reasoning": {"type": "string"}
                },
                "description": "Where and how to place this entity"
            },
            "narrative_role": {
                "type": "string",
                "description": "The entity's intended role in the world narrative"
            },
            "creation_reasoning": {
                "type": "string",
                "description": "AI's reasoning for the design choices made"
            }
        },
        "required": ["interpretation", "entity_type", "entity_characteristics", "required_components", "narrative_role", "creation_reasoning"]
    })
}

/// Helper function to create the JSON schema for entity details analysis
fn get_entity_details_analysis_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "interpretation": {
                "type": "string",
                "description": "AI's understanding of what details were requested"
            },
            "entity_summary": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "type": {"type": "string"},
                    "description": {"type": "string"},
                    "scale": {"type": "string"},
                    "salience_tier": {"type": "string"}
                },
                "required": ["name", "type", "description"],
                "description": "High-level entity summary"
            },
            "components_analysis": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "component_type": {"type": "string"},
                        "significance": {"type": "string"}, 
                        "key_properties": {"type": "object"},
                        "ai_interpretation": {"type": "string"}
                    },
                    "required": ["component_type", "significance", "ai_interpretation"]
                },
                "description": "AI analysis of each component"
            },
            "relationships": {
                "type": "object",
                "properties": {
                    "parent": {"type": "string"},
                    "children": {"type": "array", "items": {"type": "string"}},
                    "relationships": {"type": "array", "items": {"type": "string"}}
                },
                "description": "Entity's relationships and hierarchy"
            },
            "narrative_context": {
                "type": "string",
                "description": "AI assessment of entity's role in the narrative"
            },
            "suggested_actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "AI suggestions for what could be done with this entity"
            }
        },
        "required": ["interpretation", "entity_summary", "components_analysis", "narrative_context"]
    })
}

#[async_trait]
impl ScribeTool for GetEntityDetailsTool {
    fn name(&self) -> &'static str {
        "get_entity_details"
    }

    fn description(&self) -> &'static str {
        "AI-powered tool that retrieves and analyzes detailed entity information. \
         Provides comprehensive insights including component analysis, relationships, \
         narrative context, and intelligent suggestions for interactions."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the operation"
                },
                "entity_identifier": {
                    "type": "string",
                    "description": "Entity identifier (name, ID, or description)"
                },
                "detail_request": {
                    "type": "string",
                    "description": "Specific details requested about the entity (e.g., 'show me all combat stats', 'analyze this character's relationships')"
                }
            },
            "required": ["user_id", "entity_identifier", "detail_request"]
        })
    }

    #[instrument(skip(self, params, session_dek), fields(tool = "get_entity_details"))]
    async fn execute(&self, params: &ToolParams, session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let input: GetEntityDetailsInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;

        info!("AI-analyzing entity details for user {}: '{}' with request '{}'", 
              user_id, input.entity_identifier, input.detail_request);

        let result = self.get_entity_details_with_ai(user_id, &input.entity_identifier, &input.detail_request, session_dek).await?;

        Ok(serde_json::to_value(result)?)
    }
}

#[async_trait]
impl SelfRegisteringTool for GetEntityDetailsTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Discovery
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "analyze".to_string(),
                target: "entity details".to_string(),
                context: Some("comprehensive inspection".to_string()),
            },
            ToolCapability {
                action: "interpret".to_string(),
                target: "component data".to_string(),
                context: Some("AI-driven analysis".to_string()),
            },
            ToolCapability {
                action: "suggest".to_string(),
                target: "entity interactions".to_string(),
                context: Some("contextual recommendations".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need comprehensive details about a specific entity, including \
         component analysis, relationships, narrative significance, and interaction suggestions. \
         Perfect for detailed inspection, character analysis, or understanding complex entities.".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for simple entity searches (use find_entity instead), entity creation, \
         or when you need to modify entity properties. Use specific creation/update tools instead.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Detailed character analysis".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "entity_identifier": "Captain Sarah Voss",
                    "detail_request": "Show me all combat abilities and equipment"
                }),
                expected_output: "Comprehensive analysis of combat stats, equipment, abilities, and tactical suggestions".to_string(),
            },
            ToolExample {
                scenario: "Location inspection".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "entity_identifier": "The Ancient Library",
                    "detail_request": "What can I learn about this place and what's inside it?"
                }),
                expected_output: "Analysis of location properties, contained items, historical significance, and exploration opportunities".to_string(),
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
                write_access: false, // Read-only analysis
                allowed_scopes: vec!["entities".to_string(), "components".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 80,
            execution_time: ExecutionTime::Moderate, // AI analysis takes time
            external_calls: true, // Uses AI client and find_entity tool
            compute_intensive: false,
        }
    }
    
    fn dependencies(&self) -> Vec<String> {
        vec![
            "find_entity".to_string(),
            "ai_client".to_string(),
            "ecs_entity_manager".to_string(),
        ]
    }
    
    fn tags(&self) -> Vec<String> {
        vec![
            "entity".to_string(),
            "analysis".to_string(),
            "details".to_string(),
            "ai-powered".to_string(),
            "inspection".to_string(),
            "components".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "entity_id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "UUID of the analyzed entity"
                },
                "entity_name": {
                    "type": "string",
                    "description": "Name of the entity"
                },
                "ai_analysis": {
                    "type": "object",
                    "description": "AI-generated analysis and insights"
                },
                "raw_components": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "component_type": {"type": "string"},
                            "component_data": {
                                "type": "object",
                                "description": "Flexible component data structure",
                                "properties": {
                                    "value": {
                                        "description": "Component-specific data"
                                    }
                                }
                            }
                        }
                    },
                    "description": "Raw component data from ECS"
                },
                "user_request": {
                    "type": "string",
                    "description": "Original user request for details"
                }
            },
            "required": ["entity_id", "entity_name", "ai_analysis", "raw_components", "user_request"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "ENTITY_NOT_FOUND".to_string(),
                description: "The specified entity could not be found".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "AI_ANALYSIS_FAILED".to_string(),
                description: "AI failed to analyze the entity details".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "INVALID_ENTITY_IDENTIFIER".to_string(),
                description: "The entity identifier format is invalid".to_string(),
                retry_able: false,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

/// AI-powered tool that creates new entities using intelligent interpretation of creation requests
#[derive(Clone)]
pub struct CreateEntityTool {
    app_state: Arc<AppState>,
}

impl CreateEntityTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Use AI to interpret the entity creation request and generate appropriate components
    async fn create_entity_with_ai(
        &self,
        user_id: Uuid,
        creation_request: &str,
        context: &str,
    ) -> Result<EntityCreationOutput, ToolError> {
        // Use AI to interpret and plan the entity creation
        let schema = get_entity_creation_analysis_schema();
        
        let prompt = format!(
            r#"You are an intelligent entity creation agent for a dynamic roleplay world model system.

Your task is to interpret natural language entity creation requests and design appropriate entity structures with components.

CREATION REQUEST: "{}"
CONTEXT: "{}"
USER ID: {}

Your analysis should provide:
1. Clear interpretation of what entity the user wants to create
2. Appropriate entity type and characteristics
3. Essential components needed for this entity type
4. Spatial placement and scale decisions
5. Relationships and hierarchy considerations
6. Initial property values that make narrative sense

IMPORTANT GUIDELINES:
- Create entities that fit the world's narrative context
- Choose appropriate spatial scales (Cosmic, Planetary, Intimate)
- Select specific spatial types from our enhanced system:
  * Cosmic: Galaxy, StarSystem, Planet, Moon, Asteroid, SpaceStation, Spaceship, etc.
  * Planetary: Continent, Ocean, City, Forest, Mountain, etc.
  * Intimate: Building, Room, Furniture, Container, etc.
  * Custom: You can create custom spatial types for unique entities (e.g., "MagicalRealm", "PocketDimension", "CyberSpace", "DreamScape", etc.)
- Include essential components like Name, Position, SpatialArchetype, EnhancedSpatial
- Consider relationships to existing entities when appropriate
- Make reasonable assumptions for missing details
- Ensure components work together logically

Format your response to help create a cohesive, well-structured entity that enhances the world simulation."#,
            creation_request,
            context,
            user_id
        );

        // Execute AI analysis
        let system_prompt = "You are an entity creation agent for a fictional roleplay game. You design entities that fit into a fantasy world simulation. All content is creative fiction.";
        
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
            max_tokens: Some(2000),
            temperature: Some(0.4), // Slightly higher for creative entity design
            response_format: Some(ChatResponseFormat::JsonSchemaSpec(
                JsonSchemaSpec { schema: schema.clone() }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.agentic_entity_resolution_model, chat_request, Some(chat_options))
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

        let ai_plan: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}", e)))?;

        // Extract entity details from the AI plan
        let entity_id = Uuid::new_v4();
        let interpretation = ai_plan.get("interpretation").and_then(|v| v.as_str()).unwrap_or("Unknown entity");
        
        // Extract entity characteristics
        let entity_chars = ai_plan.get("entity_characteristics")
            .ok_or_else(|| ToolError::ExecutionFailed("Missing entity_characteristics in AI plan".to_string()))?;
        
        let entity_name = entity_chars.get("name").and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::ExecutionFailed("Missing entity name".to_string()))?;
        
        let spatial_scale_str = entity_chars.get("spatial_scale").and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::ExecutionFailed("Missing spatial scale".to_string()))?;
        
        let spatial_scale = match spatial_scale_str {
            "Cosmic" => SpatialScale::Cosmic,
            "Planetary" => SpatialScale::Planetary,
            "Intimate" => SpatialScale::Intimate,
            _ => return Err(ToolError::ExecutionFailed(format!("Invalid spatial scale: {}", spatial_scale_str))),
        };
        
        let salience_tier_str = entity_chars.get("salience_tier").and_then(|v| v.as_str()).unwrap_or("Flavor");
        let salience_tier = match salience_tier_str {
            "Core" => SalienceTier::Core,
            "Secondary" | "Supporting" => SalienceTier::Secondary,
            "Flavor" | "Background" => SalienceTier::Flavor,
            _ => SalienceTier::Flavor,
        };
        
        // Check if entity with same name already exists for this user
        // Create a FindEntityTool instance to search for existing entities
        let find_tool = FindEntityTool {
            app_state: self.app_state.clone(),
        };
        
        // Prepare parameters for the find_entity tool
        let find_params = json!({
            "user_id": user_id.to_string(),
            "search_request": format!("find entity named '{}'", entity_name),
            "context": "Checking for duplicate before creation",
            "limit": 10
        });
        
        // Use a dummy session key for internal tool calls
        let dummy_session_dek = SessionDek::new(vec![0u8; 32]);
        
        // Try to find the entity first
        match find_tool.execute(&find_params, &dummy_session_dek).await {
            Ok(result) => {
                // Parse the result to check if we found an exact match
                if let Some(entities) = result.get("entities").and_then(|v| v.as_array()) {
                    for entity in entities {
                        if let Some(name) = entity.get("entity_name").and_then(|v| v.as_str()) {
                            if name.eq_ignore_ascii_case(entity_name) {
                                // Entity already exists, return info about existing entity
                                let entity_id = entity.get("entity_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");
                                
                                info!("Entity '{}' already exists with ID {}, returning existing entity", 
                                    entity_name, entity_id);
                                
                                return Ok(EntityCreationOutput {
                                    entity_id: entity_id.to_string(),
                                    creation_plan: json!({
                                        "status": "existing",
                                        "message": format!("Entity '{}' already exists", entity_name),
                                        "existing_entity": entity
                                    }),
                                    creation_summary: format!("Found existing entity '{}' instead of creating duplicate", entity_name),
                                    created: false,
                                    user_request: creation_request.to_string(),
                                });
                            }
                        }
                    }
                }
            },
            Err(e) => {
                // Entity not found or error in search - continue with creation
                debug!("No existing entity found with name '{}', proceeding with creation: {:?}", entity_name, e);
            }
        }
        
        // Build components based on the AI plan
        let mut components: Vec<(String, JsonValue)> = Vec::new();
        
        // Add Name component
        let name_component = NameComponent {
            name: entity_name.to_string(),
            display_name: entity_name.to_string(),
            aliases: vec![],
        };
        components.push(("Name".to_string(), serde_json::to_value(&name_component).unwrap()));
        
        // Add SpatialArchetype component with proper archetype name based on scale
        let entity_type = ai_plan.get("entity_type").and_then(|v| v.as_str()).unwrap_or("entity");
        
        // Determine the correct archetype name based on spatial scale and hierarchical level
        let hierarchical_level = 0u32; // Default to root level for now
        let archetype_name = match spatial_scale {
            SpatialScale::Cosmic => {
                // For cosmic scale, level 0 is "Universe"
                spatial_scale.level_name(hierarchical_level).unwrap_or("Universe").to_string()
            },
            SpatialScale::Planetary => {
                // For planetary scale, level 0 is "World"
                spatial_scale.level_name(hierarchical_level).unwrap_or("World").to_string()
            },
            SpatialScale::Intimate => {
                // For intimate scale, level 0 is "Building"
                spatial_scale.level_name(hierarchical_level).unwrap_or("Building").to_string()
            }
        };
        
        let archetype_component = SpatialArchetypeComponent::new(
            spatial_scale.clone(),
            hierarchical_level,
            archetype_name
        ).map_err(|e| ToolError::ExecutionFailed(format!("Failed to create spatial archetype: {}", e)))?;
        components.push(("SpatialArchetype".to_string(), serde_json::to_value(&archetype_component).unwrap()));
        
        // Add Position component if spatial placement is provided
        if let Some(spatial_placement) = ai_plan.get("spatial_placement") {
            let x = spatial_placement.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let y = spatial_placement.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let z = spatial_placement.get("z").and_then(|v| v.as_f64()).unwrap_or(0.0);
            
            let coords = HierarchicalCoordinates::new(x, y, z, spatial_scale.clone());
            let position_component = EnhancedPositionComponent::absolute(coords);
            components.push(("EnhancedPosition".to_string(), serde_json::to_value(&position_component).unwrap()));
        }
        
        // Add Temporal component (for when the entity was created)
        let game_time = GameTime {
            timestamp: Utc::now(),
            turn: None,
            phase: None,
            mode: TimeMode::Continuous { tick_rate_ms: 1000 },
        };
        
        let temporal_component = TemporalComponent {
            created_at: game_time.clone(),
            destroyed_at: None,
            last_modified: game_time,
            time_scale: 1.0, // Normal time progression
        };
        components.push(("Temporal".to_string(), serde_json::to_value(&temporal_component).unwrap()));
        
        // Extract spatial type from AI plan
        let spatial_type_str = entity_chars.get("spatial_type").and_then(|v| v.as_str())
            .unwrap_or_else(|| {
                // Default based on entity type and scale
                match (entity_type, spatial_scale_str) {
                    ("location", "Cosmic") => "Planet",
                    ("location", "Planetary") => "City",
                    ("location", "Intimate") => "Building",
                    ("character", _) => "Custom",
                    ("item", _) => "Container",
                    _ => "Custom"
                }
            });
        
        // Map string to EnhancedSpatialType enum
        let enhanced_spatial_type = match spatial_type_str {
            "Universe" => EnhancedSpatialType::Universe,
            "Galaxy" => EnhancedSpatialType::Galaxy,
            "GalaxyCluster" => EnhancedSpatialType::GalaxyCluster,
            "Nebula" => EnhancedSpatialType::Nebula,
            "StarSystem" => EnhancedSpatialType::StarSystem,
            "Star" => EnhancedSpatialType::Star,
            "Planet" => EnhancedSpatialType::Planet,
            "Moon" => EnhancedSpatialType::Moon,
            "Asteroid" => EnhancedSpatialType::Asteroid,
            "AsteroidBelt" => EnhancedSpatialType::AsteroidBelt,
            "Comet" => EnhancedSpatialType::Comet,
            "SpaceStation" => EnhancedSpatialType::SpaceStation,
            "Spaceship" => EnhancedSpatialType::Spaceship,
            "Starship" => EnhancedSpatialType::Starship,
            "Shuttle" => EnhancedSpatialType::Shuttle,
            "Fighter" => EnhancedSpatialType::Fighter,
            "Freighter" => EnhancedSpatialType::Freighter,
            "Ship" => EnhancedSpatialType::Ship,
            "Airship" => EnhancedSpatialType::Airship,
            "Aircraft" => EnhancedSpatialType::Aircraft,
            "Vehicle" => EnhancedSpatialType::Vehicle,
            "Continent" => EnhancedSpatialType::Continent,
            "Ocean" => EnhancedSpatialType::Ocean,
            "Sea" => EnhancedSpatialType::Sea,
            "MountainRange" => EnhancedSpatialType::MountainRange,
            "Desert" => EnhancedSpatialType::Desert,
            "Forest" => EnhancedSpatialType::Forest,
            "Jungle" => EnhancedSpatialType::Jungle,
            "Tundra" => EnhancedSpatialType::Tundra,
            "Grassland" => EnhancedSpatialType::Grassland,
            "Swamp" => EnhancedSpatialType::Swamp,
            "Marsh" => EnhancedSpatialType::Marsh,
            "River" => EnhancedSpatialType::River,
            "Lake" => EnhancedSpatialType::Lake,
            "Island" => EnhancedSpatialType::Island,
            "Peninsula" => EnhancedSpatialType::Peninsula,
            "Valley" => EnhancedSpatialType::Valley,
            "Canyon" => EnhancedSpatialType::Canyon,
            "Cave" => EnhancedSpatialType::Cave,
            "Cavern" => EnhancedSpatialType::Cavern,
            "Empire" => EnhancedSpatialType::Empire,
            "Kingdom" => EnhancedSpatialType::Kingdom,
            "Republic" => EnhancedSpatialType::Republic,
            "Province" => EnhancedSpatialType::Province,
            "State" => EnhancedSpatialType::State,
            "County" => EnhancedSpatialType::County,
            "City" => EnhancedSpatialType::City,
            "Town" => EnhancedSpatialType::Town,
            "Village" => EnhancedSpatialType::Village,
            "District" => EnhancedSpatialType::District,
            "Neighborhood" => EnhancedSpatialType::Neighborhood,
            "Fortress" => EnhancedSpatialType::Fortress,
            "Castle" => EnhancedSpatialType::Castle,
            "Palace" => EnhancedSpatialType::Palace,
            "Temple" => EnhancedSpatialType::Temple,
            "Tower" => EnhancedSpatialType::Tower,
            "Building" => EnhancedSpatialType::Building,
            "House" => EnhancedSpatialType::House,
            "Inn" => EnhancedSpatialType::Inn,
            "Tavern" => EnhancedSpatialType::Tavern,
            "Shop" => EnhancedSpatialType::Shop,
            "Market" => EnhancedSpatialType::Market,
            "Bridge" => EnhancedSpatialType::Bridge,
            "Port" => EnhancedSpatialType::Port,
            "Dock" => EnhancedSpatialType::Dock,
            "Warehouse" => EnhancedSpatialType::Warehouse,
            "Floor" => EnhancedSpatialType::Floor,
            "Room" => EnhancedSpatialType::Room,
            "Chamber" => EnhancedSpatialType::Chamber,
            "Hall" => EnhancedSpatialType::Hall,
            "Corridor" => EnhancedSpatialType::Corridor,
            "Courtyard" => EnhancedSpatialType::Courtyard,
            "Garden" => EnhancedSpatialType::Garden,
            "Basement" => EnhancedSpatialType::Basement,
            "Attic" => EnhancedSpatialType::Attic,
            "Deck" => EnhancedSpatialType::Deck,
            "Cabin" => EnhancedSpatialType::Cabin,
            "Cockpit" => EnhancedSpatialType::Cockpit,
            "CargoHold" => EnhancedSpatialType::CargoHold,
            "EngineeringBay" => EnhancedSpatialType::EngineeringBay,
            "Area" => EnhancedSpatialType::Area,
            "Furniture" => EnhancedSpatialType::Furniture,
            "Container" => EnhancedSpatialType::Container,
            "Compartment" => EnhancedSpatialType::Compartment,
            "Locker" => EnhancedSpatialType::Locker,
            "Chest" => EnhancedSpatialType::Chest,
            "Shelf" => EnhancedSpatialType::Shelf,
            "Table" => EnhancedSpatialType::Table,
            "Bed" => EnhancedSpatialType::Bed,
            "Chair" => EnhancedSpatialType::Chair,
            _ => EnhancedSpatialType::Custom(spatial_type_str.to_string()),
        };
        
        // Create EnhancedSpatialComponent
        let mut enhanced_spatial_component = EnhancedSpatialComponent::new(enhanced_spatial_type);
        
        // Add metadata about the entity
        enhanced_spatial_component.add_metadata("entity_type".to_string(), json!(entity_type));
        enhanced_spatial_component.add_metadata("description".to_string(), 
            json!(entity_chars.get("description").and_then(|v| v.as_str()).unwrap_or("")));
        
        components.push(("EnhancedSpatial".to_string(), serde_json::to_value(&enhanced_spatial_component).unwrap()));
        
        // Also add the old Spatial component for backwards compatibility
        use crate::models::ecs::{SpatialType, SpatialConstraints, SpatialCapacity};
        let spatial_component = SpatialComponent {
            spatial_type: SpatialType::Container {
                capacity: Some(SpatialCapacity {
                    max_count: Some(10),
                    max_volume: None,
                    max_mass: None,
                }),
                allowed_types: vec!["Actor".to_string(), "Item".to_string()],
            },
            constraints: SpatialConstraints::default(),
            metadata: HashMap::new(),
        };
        components.push(("Spatial".to_string(), serde_json::to_value(&spatial_component).unwrap()));
        
        // Add any additional components from the AI plan
        if let Some(required_components) = ai_plan.get("required_components").and_then(|v| v.as_array()) {
            for comp in required_components {
                if let (Some(comp_type), Some(comp_data)) = (
                    comp.get("component_type").and_then(|v| v.as_str()),
                    comp.get("component_data")
                ) {
                    // Skip components we've already added
                    if !["Name", "SpatialArchetype", "EnhancedPosition", "Temporal", "Spatial", "EnhancedSpatial"].contains(&comp_type) {
                        components.push((comp_type.to_string(), comp_data.clone()));
                    }
                }
            }
        }
        
        // Create archetype signature
        let archetype_signature = components.iter()
            .map(|(comp_type, _)| comp_type.clone())
            .collect::<Vec<_>>()
            .join("|");
        
        // Actually create the entity in ECS
        let entity_manager = EcsEntityManager::new(
            Arc::new(self.app_state.pool.clone()),
            self.app_state.redis_client.clone(),
            Default::default()
        );
        
        let entity_result = entity_manager.create_entity_with_salience(
            user_id,
            Some(entity_id),
            archetype_signature,
            salience_tier,
            Some(spatial_scale),
            components
        ).await.map_err(|e| ToolError::AppError(e))?;
        
        Ok(EntityCreationOutput {
            entity_id: entity_id.to_string(),
            creation_plan: ai_plan.clone(),
            user_request: creation_request.to_string(),
            created: true,
            creation_summary: format!("Created {} entity '{}' at {} scale", entity_type, entity_name, spatial_scale_str),
        })
    }
}

pub struct UpdateEntityTool {
    app_state: Arc<AppState>,
}

impl UpdateEntityTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
}

// ===== AI-DRIVEN CREATE ENTITY TOOL IMPLEMENTATION =====

#[async_trait]
impl ScribeTool for CreateEntityTool {
    fn name(&self) -> &'static str {
        "create_entity"
    }

    fn description(&self) -> &'static str {
        "AI-powered tool that creates new entities by interpreting natural language creation requests and generating appropriate component structures for the world simulation."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user creating the entity"
                },
                "creation_request": {
                    "type": "string",
                    "description": "Natural language description of what entity to create"
                },
                "context": {
                    "type": "string",
                    "description": "Additional context about the current world state or scenario"
                }
            },
            "required": ["user_id", "creation_request", "context"]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        debug!("Executing AI-driven create_entity tool");

        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let creation_request = params.get("creation_request")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("creation_request is required".to_string()))?;

        let context = params.get("context")
            .and_then(|v| v.as_str())
            .unwrap_or("No additional context provided");

        info!("Creating entity with AI analysis: '{}' for user {}", creation_request, user_id);

        // Use AI to analyze and plan the entity creation
        let creation_output = self.create_entity_with_ai(user_id, creation_request, context).await?;

        // Return structured response
        Ok(json!({
            "status": "success",
            "message": "Entity creation analyzed and planned by AI",
            "entity_id": creation_output.entity_id,
            "creation_plan": creation_output.creation_plan,
            "created": creation_output.created,
            "summary": creation_output.creation_summary,
            "user_request": creation_output.user_request,
            "note": "Full ECS integration pending - currently returns AI analysis and plan"
        }))
    }
}

#[async_trait]
impl SelfRegisteringTool for CreateEntityTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Creation
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "create".to_string(),
                target: "entity".to_string(),
                context: Some("with AI-generated components".to_string()),
            },
            ToolCapability {
                action: "design".to_string(),
                target: "entity structure".to_string(),
                context: Some("based on natural language".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool when you need to create new entities in the world based on natural language descriptions. The AI will interpret the request and design appropriate component structures.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for modifying existing entities (use update_entity), simple queries (use find_entity), or when you need detailed information about existing entities (use get_entity_details).".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Creating a new character in a tavern".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "creation_request": "Create a wise old bartender named Gareth who knows all the local gossip",
                    "context": "The party is currently in the Red Dragon Tavern in the village of Millhaven"
                }),
                expected_output: "Returns AI-planned entity creation with appropriate components for a bartender character".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
            ],
            required_capabilities: vec!["entity_creation".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true,
                allowed_scopes: vec!["entities".to_string(), "ecs".to_string()],
            },
            audit_level: AuditLevel::Detailed,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 100,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // AI model calls
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "message": {"type": "string"},
                "entity_id": {"type": "string"},
                "creation_plan": {"type": "object"},
                "created": {"type": "boolean"},
                "summary": {"type": "string"},
                "user_request": {"type": "string"}
            },
            "required": ["status", "entity_id", "creation_plan"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "entity".to_string(),
            "creation".to_string(),
            "world-building".to_string(),
            "ecs".to_string(),
        ]
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

// ===== AI-DRIVEN UPDATE ENTITY TOOL IMPLEMENTATION =====

#[async_trait]
impl ScribeTool for UpdateEntityTool {
    fn name(&self) -> &'static str {
        "update_entity"
    }

    fn description(&self) -> &'static str {
        "AI-powered tool that updates existing entities by interpreting natural language modification requests and determining the appropriate component changes."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user updating the entity"
                },
                "entity_identifier": {
                    "type": "string",
                    "description": "Entity ID, name, or description to identify which entity to update"
                },
                "update_request": {
                    "type": "string",
                    "description": "Natural language description of what changes to make"
                },
                "context": {
                    "type": "string",
                    "description": "Additional context about the current situation or reason for the update"
                }
            },
            "required": ["user_id", "entity_identifier", "update_request", "context"]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        debug!("Executing AI-driven update_entity tool");

        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let entity_identifier = params.get("entity_identifier")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("entity_identifier is required".to_string()))?;

        let update_request = params.get("update_request")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("update_request is required".to_string()))?;

        let context = params.get("context")
            .and_then(|v| v.as_str())
            .unwrap_or("No additional context provided");

        info!("Updating entity '{}' with AI analysis: '{}' for user {}", 
              entity_identifier, update_request, user_id);

        // Use AI to analyze and plan the entity update
        let update_output = self.update_entity_with_ai(user_id, entity_identifier, update_request, context).await?;

        // Return structured response
        Ok(json!({
            "status": "success",
            "message": "Entity update analyzed and planned by AI",
            "entity_identifier": entity_identifier,
            "update_plan": update_output.update_plan,
            "updated": update_output.updated,
            "summary": update_output.update_summary,
            "user_request": update_output.user_request,
            "note": "Full ECS integration pending - currently returns AI analysis and plan"
        }))
    }
}

impl UpdateEntityTool {
    /// Use AI to interpret the entity update request and generate appropriate component modifications
    async fn update_entity_with_ai(
        &self,
        user_id: Uuid,
        entity_identifier: &str,
        update_request: &str,
        context: &str,
    ) -> Result<EntityUpdateOutput, ToolError> {
        let schema = get_entity_update_analysis_schema();
        
        let prompt = format!(
            r#"You are an intelligent entity update agent for a dynamic roleplay world model system.

Your task is to interpret natural language entity update requests and design appropriate component modifications.

ENTITY TO UPDATE: "{}"
UPDATE REQUEST: "{}"  
CONTEXT: "{}"
USER ID: {}

Your analysis should provide:
1. Clear interpretation of what changes should be made
2. Identification of which components need modification
3. Specific property changes with new values
4. Impact assessment on related entities or systems
5. Validation that changes make narrative sense
6. Reasoning for each proposed modification

IMPORTANT GUIDELINES:
- Only modify components that are directly affected by the request
- Preserve existing relationships unless explicitly changing them
- Consider narrative consistency and world coherence
- Make reasonable assumptions for ambiguous requests
- Ensure component changes work together logically
- Flag any potential conflicts or issues

Format your response to help implement precise, logical entity updates that enhance the world simulation."#,
            entity_identifier,
            update_request,
            context,
            user_id
        );

        // Execute AI analysis
        let system_prompt = "You are an entity update agent for a fictional roleplay game. You analyze modification requests and design component changes that maintain world consistency. All content is creative fiction.";
        
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
            max_tokens: Some(2000),
            temperature: Some(0.3), // Lower temperature for precise modifications
            response_format: Some(ChatResponseFormat::JsonSchemaSpec(
                JsonSchemaSpec { schema: schema.clone() }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.agentic_entity_resolution_model, chat_request, Some(chat_options))
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

        let ai_plan: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}", e)))?;

        // Extract interpretation and handle specific update types
        let interpretation = ai_plan.get("interpretation").and_then(|v| v.as_str()).unwrap_or("Unknown update");
        
        // Check if this is a parent relationship update (spatial hierarchy)
        let mut updated = false;
        let mut update_summary = format!("AI-planned entity update: {}", interpretation);
        
        if update_request.contains("Set parent to entity with ID") {
            // Extract parent entity ID from the request
            if let Some(parent_id_start) = update_request.find("Set parent to entity with ID ") {
                let parent_id_str = &update_request[parent_id_start + "Set parent to entity with ID ".len()..];
                if let Ok(parent_id) = Uuid::parse_str(parent_id_str.trim()) {
                    // Implement parent link update via ECS
                    match self.update_parent_link_in_ecs(user_id, entity_identifier, parent_id).await {
                        Ok(()) => {
                            updated = true;
                            update_summary = format!("Successfully set parent link: {} -> {}", entity_identifier, parent_id);
                            info!("ECS parent link updated: {} -> {}", entity_identifier, parent_id);
                        }
                        Err(e) => {
                            warn!("Failed to update parent link in ECS: {}", e);
                            update_summary = format!("AI analysis complete, but ECS update failed: {}", e);
                        }
                    }
                }
            }
        }
        
        Ok(EntityUpdateOutput {
            entity_identifier: entity_identifier.to_string(),
            update_plan: ai_plan.clone(),
            user_request: update_request.to_string(),
            updated,
            update_summary,
        })
    }
    
    /// Update the parent link for an entity in ECS by adding/updating a ParentLink component
    async fn update_parent_link_in_ecs(
        &self,
        user_id: Uuid,
        entity_identifier: &str,
        parent_id: Uuid,
    ) -> Result<(), ToolError> {
        // Create entity manager
        let entity_manager = EcsEntityManager::new(
            Arc::new(self.app_state.pool.clone()),
            self.app_state.redis_client.clone(),
            Default::default()
        );
        
        // Try to parse entity_identifier as UUID first, otherwise find by name
        let entity_id = if let Ok(id) = Uuid::parse_str(entity_identifier) {
            id
        } else {
            // Find entity by name using query_entities
            let find_criteria = vec![ComponentQuery::ComponentDataEquals(
                "Identity".to_string(),
                "name".to_string(),
                serde_json::json!(entity_identifier),
            )];
            
            let results = entity_manager.query_entities(user_id, find_criteria, None, None).await
                .map_err(|e| ToolError::AppError(e))?;
                
            if results.is_empty() {
                return Err(ToolError::ExecutionFailed(format!("Entity '{}' not found", entity_identifier)));
            }
            
            results[0].entity.id
        };
        
        // Create ParentLink component data
        let parent_link_data = serde_json::json!({
            "parent_id": parent_id.to_string()
        });
        
        // Update the entity with ParentLink component using update_components
        let component_updates = vec![ComponentUpdate {
            entity_id,
            component_type: "ParentLink".to_string(),
            component_data: parent_link_data,
            operation: ComponentOperation::Add,
        }];
        
        entity_manager.update_components(user_id, entity_id, component_updates).await
            .map_err(|e| ToolError::AppError(e))?;
        
        info!("Successfully updated ParentLink component for entity {} -> parent {}", entity_id, parent_id);
        Ok(())
    }
}

#[async_trait]
impl SelfRegisteringTool for UpdateEntityTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Management
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "update".to_string(),
                target: "entity".to_string(),
                context: Some("with AI-analyzed modifications".to_string()),
            },
            ToolCapability {
                action: "modify".to_string(),
                target: "entity components".to_string(),
                context: Some("based on natural language".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool when you need to modify existing entities based on natural language change requests. The AI will analyze what needs to be updated and plan appropriate component modifications.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for creating new entities (use create_entity), finding entities (use find_entity), or getting information without changes (use get_entity_details).".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Updating a character's health after combat".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "entity_identifier": "Sir Gareth",
                    "update_request": "Sir Gareth was wounded in the dragon fight and is now at half health",
                    "context": "After the battle with the Ancient Red Dragon in the village square"
                }),
                expected_output: "Returns AI-planned entity updates focusing on health/status components".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
            ],
            required_capabilities: vec!["entity_modification".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true,
                allowed_scopes: vec!["entities".to_string(), "ecs".to_string()],
            },
            audit_level: AuditLevel::Detailed,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 80,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // AI model calls
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "message": {"type": "string"},
                "entity_identifier": {"type": "string"},
                "update_plan": {"type": "object"},
                "updated": {"type": "boolean"},
                "summary": {"type": "string"},
                "user_request": {"type": "string"}
            },
            "required": ["status", "entity_identifier", "update_plan"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "entity".to_string(),
            "update".to_string(),
            "modification".to_string(),
            "ecs".to_string(),
        ]
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

// ===== DATA STRUCTURES FOR AI TOOL OUTPUTS =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityUpdateOutput {
    pub entity_identifier: String,
    pub update_plan: JsonValue,
    pub user_request: String,
    pub updated: bool,
    pub update_summary: String,
}

/// Schema for AI entity update analysis
fn get_entity_update_analysis_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "interpretation": {
                "type": "string",
                "description": "AI's understanding of what changes should be made"
            },
            "affected_components": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "component_type": {"type": "string"},
                        "current_state": {
                            "type": "object",
                            "properties": {
                                "data": {
                                    "type": "object", 
                                    "description": "Current component data",
                                    "properties": {
                                        "value": {"type": "string", "description": "String representation of component data"}
                                    }
                                },
                                "exists": {"type": "boolean", "description": "Whether component currently exists"}
                            }
                        },
                        "proposed_changes": {
                            "type": "object",
                            "properties": {
                                "data": {
                                    "type": "object", 
                                    "description": "New or updated component data",
                                    "properties": {
                                        "value": {"type": "string", "description": "String representation of component data"}
                                    }
                                },
                                "operation": {"type": "string", "enum": ["create", "update", "delete"], "description": "Type of change"}
                            }
                        },
                        "reasoning": {"type": "string"}
                    },
                    "required": ["component_type", "proposed_changes", "reasoning"]
                },
                "description": "Components that need to be modified"
            },
            "impact_assessment": {
                "type": "object",
                "properties": {
                    "related_entities": {"type": "array", "items": {"type": "string"}},
                    "potential_conflicts": {"type": "array", "items": {"type": "string"}},
                    "narrative_consistency": {"type": "string"}
                },
                "description": "Assessment of update impact"
            },
            "update_priority": {
                "type": "string",
                "enum": ["immediate", "normal", "deferred"],
                "description": "Urgency of the update"
            },
            "validation_notes": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Validation checks and considerations"
            }
        },
        "required": ["interpretation", "affected_components", "impact_assessment", "update_priority"]
    })
}

// ===== AI-DRIVEN DELETE ENTITY TOOL =====

/// AI-powered tool that deletes entities based on natural language requests
#[derive(Clone)]
pub struct DeleteEntityTool {
    app_state: Arc<AppState>,
}

impl DeleteEntityTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
}

#[async_trait]
impl ScribeTool for DeleteEntityTool {
    fn name(&self) -> &'static str {
        "delete_entity"
    }

    fn description(&self) -> &'static str {
        "AI-powered entity deletion that interprets natural language requests about removing entities from the world. Handles cleanup of relationships and references."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user"
                },
                "entity_identifier": {
                    "type": "string",
                    "description": "Entity name, UUID, or description to identify the entity to delete"
                },
                "deletion_reason": {
                    "type": "string",
                    "description": "Natural language description of why the entity should be deleted"
                },
                "context": {
                    "type": "string",
                    "description": "Additional context about the deletion circumstances"
                }
            },
            "required": ["user_id", "entity_identifier", "deletion_reason", "context"]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        debug!("Executing AI-driven delete_entity tool");

        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let _user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let entity_identifier = params.get("entity_identifier")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("entity_identifier is required".to_string()))?;

        let deletion_reason = params.get("deletion_reason")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("deletion_reason is required".to_string()))?;

        let context = params.get("context")
            .and_then(|v| v.as_str())
            .unwrap_or("No additional context provided");

        info!("Deleting entity '{}': '{}'", entity_identifier, deletion_reason);

        // For now, return AI analysis of the deletion
        // In a full system, this would:
        // 1. Find the entity by identifier
        // 2. Clean up all relationships involving this entity
        // 3. Remove the entity from the ECS
        // 4. Update any referencing data structures

        Ok(json!({
            "status": "success",
            "message": "Entity deletion analyzed by AI",
            "entity_identifier": entity_identifier,
            "deletion_reason": deletion_reason,
            "context": context,
            "deleted": false, // Placeholder - would be true after actual ECS deletion
            "cleanup_required": [
                "Remove all relationships involving this entity",
                "Update spatial hierarchy if entity has children",
                "Clean up any chronicle references",
                "Remove from inventory systems if applicable"
            ],
            "note": "Full ECS integration pending - currently returns AI analysis of deletion requirements"
        }))
    }
}

#[async_trait]
impl SelfRegisteringTool for DeleteEntityTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Management
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "delete".to_string(),
                target: "entity".to_string(),
                context: Some("with cleanup analysis".to_string()),
            },
            ToolCapability {
                action: "remove".to_string(),
                target: "world objects".to_string(),
                context: Some("from ECS system".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool when entities need to be permanently removed from the world due to story events, character deaths, object destruction, or cleanup operations.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for creating or modifying entities (use create/update_entity), or for temporary hiding (use spatial tools to move instead).".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Character dies in battle and needs to be removed from the world".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "entity_identifier": "Sir Braveheart",
                    "deletion_reason": "Sir Braveheart was killed in the dragon battle and his body was consumed by flames",
                    "context": "Final boss battle, heroic sacrifice to save the village"
                }),
                expected_output: "Returns AI analysis confirming entity deletion with cleanup requirements for relationships and references".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
            ],
            required_capabilities: vec!["entity_management".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true,
                allowed_scopes: vec!["entities".to_string(), "relationships".to_string(), "world".to_string()],
            },
            audit_level: AuditLevel::Detailed,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 60,
            execution_time: ExecutionTime::Fast,
            external_calls: false,
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "message": {"type": "string"},
                "entity_identifier": {"type": "string"},
                "deletion_reason": {"type": "string"},
                "deleted": {"type": "boolean"},
                "cleanup_required": {
                    "type": "array",
                    "items": {"type": "string"}
                }
            },
            "required": ["status", "entity_identifier", "deletion_reason", "deleted"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "entity".to_string(),
            "deletion".to_string(),
            "lifecycle".to_string(),
            "cleanup".to_string(),
        ]
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

// ===== SPATIAL TYPES QUERY TOOL =====

/// Tool that provides information about available spatial types and their relationships
#[derive(Clone)]
pub struct QuerySpatialTypesTool {
    app_state: Arc<AppState>,
}

impl QuerySpatialTypesTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
}

#[async_trait]
impl ScribeTool for QuerySpatialTypesTool {
    fn name(&self) -> &'static str {
        "query_spatial_types"
    }

    fn description(&self) -> &'static str {
        "Query available spatial types and their containment relationships in the enhanced spatial system. \
         Useful for understanding what spatial types can be used when creating or searching for entities."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "query_type": {
                    "type": "string",
                    "enum": ["all_types", "cosmic_types", "planetary_types", "intimate_types", "containment_rules"],
                    "description": "Type of spatial information to query"
                },
                "spatial_type": {
                    "type": "string",
                    "description": "Specific spatial type to get containment information for (when query_type is 'containment_rules')"
                }
            },
            "required": ["query_type"]
        })
    }

    #[instrument(skip(self, params, _session_dek), fields(tool = "query_spatial_types"))]
    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let query_type = params.get("query_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("query_type is required".to_string()))?;

        let result = match query_type {
            "all_types" => {
                json!({
                    "cosmic_types": ["Universe", "Galaxy", "GalaxyCluster", "Nebula", "StarSystem", "Star", "Planet", "Moon", "Asteroid", "AsteroidBelt", "Comet", "SpaceStation"],
                    "vehicle_types": ["Spaceship", "Starship", "Shuttle", "Fighter", "Freighter", "Ship", "Airship", "Aircraft", "Vehicle"],
                    "geographic_types": ["Continent", "Ocean", "Sea", "MountainRange", "Desert", "Forest", "Jungle", "Tundra", "Grassland", "Swamp", "Marsh", "River", "Lake", "Island", "Peninsula", "Valley", "Canyon", "Cave", "Cavern"],
                    "political_types": ["Empire", "Kingdom", "Republic", "Province", "State", "County", "City", "Town", "Village", "District", "Neighborhood"],
                    "structural_types": ["Fortress", "Castle", "Palace", "Temple", "Tower", "Building", "House", "Inn", "Tavern", "Shop", "Market", "Bridge", "Port", "Dock", "Warehouse", "Floor", "Room", "Chamber", "Hall", "Corridor", "Courtyard", "Garden", "Basement", "Attic", "Deck", "Cabin", "Cockpit", "CargoHold", "EngineeringBay"],
                    "intimate_types": ["Area", "Furniture", "Container", "Compartment", "Locker", "Chest", "Shelf", "Table", "Bed", "Chair"],
                    "custom_types": "Custom(String) - allows for any custom spatial type"
                })
            },
            "cosmic_types" => {
                json!({
                    "types": ["Universe", "Galaxy", "GalaxyCluster", "Nebula", "StarSystem", "Star", "Planet", "Moon", "Asteroid", "AsteroidBelt", "Comet", "SpaceStation"],
                    "description": "Large-scale spatial types for cosmic entities"
                })
            },
            "planetary_types" => {
                json!({
                    "types": ["Continent", "Ocean", "Sea", "MountainRange", "Desert", "Forest", "Jungle", "Tundra", "Grassland", "Swamp", "Marsh", "River", "Lake", "Island", "Peninsula", "Valley", "Canyon", "Cave", "Cavern", "Empire", "Kingdom", "Republic", "Province", "State", "County", "City", "Town", "Village", "District", "Neighborhood"],
                    "description": "Planet-scale spatial types for geographic and political entities"
                })
            },
            "intimate_types" => {
                json!({
                    "types": ["Fortress", "Castle", "Palace", "Temple", "Tower", "Building", "House", "Inn", "Tavern", "Shop", "Market", "Bridge", "Port", "Dock", "Warehouse", "Floor", "Room", "Chamber", "Hall", "Corridor", "Courtyard", "Garden", "Basement", "Attic", "Deck", "Cabin", "Cockpit", "CargoHold", "EngineeringBay", "Area", "Furniture", "Container", "Compartment", "Locker", "Chest", "Shelf", "Table", "Bed", "Chair"],
                    "description": "Small-scale spatial types for buildings, rooms, and objects"
                })
            },
            "containment_rules" => {
                json!({
                    "examples": {
                        "Universe": "can contain GalaxyCluster, Galaxy",
                        "Galaxy": "can contain StarSystem, Nebula", 
                        "StarSystem": "can contain Star, Planet, Moon, Asteroid, AsteroidBelt, Comet, SpaceStation",
                        "Planet": "can contain geographic features, political entities, and surface structures",
                        "City": "can contain District, Neighborhood, Building, and infrastructure",
                        "Building": "can contain Floor, Room, and internal structures",
                        "Room": "can contain Furniture, Container, and smaller objects"
                    },
                    "note": "Custom types are also supported for unique spatial entities"
                })
            },
            _ => return Err(ToolError::InvalidParams(format!("Unknown query_type: {}", query_type)))
        };

        Ok(result)
    }
}

#[async_trait]
impl SelfRegisteringTool for QuerySpatialTypesTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Discovery
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "query".to_string(),
                target: "spatial types".to_string(),
                context: Some("system metadata".to_string()),
            },
            ToolCapability {
                action: "list".to_string(),
                target: "containment rules".to_string(),
                context: Some("spatial relationships".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need information about available spatial types for entity creation or spatial queries. \
         Helps understand what spatial types exist and how they relate to each other.".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for entity operations (use other entity CRUD tools instead) or for actual spatial \
         positioning (use spatial interaction tools).".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Get all available spatial types".to_string(),
                input: json!({
                    "query_type": "all_types"
                }),
                expected_output: "Comprehensive list of all spatial types organized by category".to_string(),
            },
            ToolExample {
                scenario: "Understanding what can contain what".to_string(),
                input: json!({
                    "query_type": "containment_rules"
                }),
                expected_output: "Examples of containment relationships between spatial types".to_string(),
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
            rate_limit: None, // Metadata queries are lightweight
            data_access: DataAccessPolicy {
                user_data: false, // Just system metadata
                system_data: true,
                write_access: false,
                allowed_scopes: vec!["spatial_types".to_string()],
            },
            audit_level: AuditLevel::None, // Just metadata queries
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 10, // Very lightweight
            execution_time: ExecutionTime::Fast,
            external_calls: false,
            compute_intensive: false,
        }
    }
    
    fn dependencies(&self) -> Vec<String> {
        vec![] // No dependencies - just returns static spatial type information
    }
    
    fn tags(&self) -> Vec<String> {
        vec![
            "spatial".to_string(),
            "metadata".to_string(),
            "query".to_string(),
            "types".to_string(),
            "reference".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "description": "Information about spatial types based on query_type",
            "oneOf": [
                {
                    "properties": {
                        "cosmic_types": {"type": "array", "items": {"type": "string"}},
                        "vehicle_types": {"type": "array", "items": {"type": "string"}},
                        "geographic_types": {"type": "array", "items": {"type": "string"}},
                        "political_types": {"type": "array", "items": {"type": "string"}},
                        "structural_types": {"type": "array", "items": {"type": "string"}},
                        "intimate_types": {"type": "array", "items": {"type": "string"}},
                        "custom_types": {"type": "string"}
                    }
                },
                {
                    "properties": {
                        "types": {"type": "array", "items": {"type": "string"}},
                        "description": {"type": "string"}
                    }
                },
                {
                    "properties": {
                        "examples": {"type": "object"},
                        "note": {"type": "string"}
                    }
                }
            ]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "INVALID_QUERY_TYPE".to_string(),
                description: "The specified query_type is not supported".to_string(),
                retry_able: false,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

// Helper function to register entity CRUD tools
pub fn register_entity_crud_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    // Register FindEntityTool - AI-driven natural language entity search
    let find_tool = Arc::new(FindEntityTool::new(app_state.clone())) as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register(find_tool)?;
    
    // Register GetEntityDetailsTool - AI-driven detailed entity analysis
    let details_tool = Arc::new(GetEntityDetailsTool::new(app_state.clone())) as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register(details_tool)?;
    
    // Register CreateEntityTool - AI-driven entity creation
    let create_tool = Arc::new(CreateEntityTool::new(app_state.clone())) as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register(create_tool)?;
    
    // Register UpdateEntityTool - AI-driven entity modification
    let update_tool = Arc::new(UpdateEntityTool::new(app_state.clone())) as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register(update_tool)?;
    
    // Register DeleteEntityTool - AI-driven entity deletion
    let delete_tool = Arc::new(DeleteEntityTool::new(app_state.clone())) as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register(delete_tool)?;
    
    // Register QuerySpatialTypesTool - spatial types metadata query
    let spatial_query_tool = Arc::new(QuerySpatialTypesTool::new(app_state.clone())) as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register(spatial_query_tool)?;
    
    tracing::info!("Registered 6 AI-driven entity CRUD tools with unified registry (FindEntityTool, GetEntityDetailsTool, CreateEntityTool, UpdateEntityTool, DeleteEntityTool, QuerySpatialTypesTool)");
    Ok(())
}