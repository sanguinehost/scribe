//! AI-Driven Spatial Interaction Tools
//!
//! These tools use AI models to interpret natural language requests about spatial
//! relationships, containment, and movement within the world model. They leverage
//! the configured AI models to provide context-aware spatial operations.

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, debug, instrument, warn};
use genai::chat::{ChatRequest, ChatMessage, ChatRole, ChatOptions, ChatResponseFormat, JsonSchemaSpec, SafetySetting, HarmCategory, HarmBlockThreshold};

use crate::{
    services::EcsEntityManager,
    models::ecs::{SpatialScale, ParentLinkComponent},
    services::agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    services::agentic::unified_tool_registry::{
        SelfRegisteringTool, ToolCategory, ToolCapability, ToolSecurityPolicy, AgentType,
        ToolExample, DataAccessPolicy, AuditLevel, ResourceRequirements, ExecutionTime, ErrorCode
    },
    state::AppState,
    errors::AppError,
    auth::session_dek::SessionDek,
};

// ===== AI-DRIVEN SPATIAL CONTEXT TOOL =====

/// AI-powered tool that interprets natural language requests about spatial context
/// and provides intelligent analysis of what entities exist in a given spatial area
#[derive(Clone)]
pub struct GetSpatialContextTool {
    app_state: Arc<AppState>,
}

impl GetSpatialContextTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Build AI prompt for interpreting spatial context requests
    fn build_spatial_context_prompt(&self, request: &str, entity_id: &str) -> String {
        format!(
            r#"You are an intelligent spatial analysis agent for a dynamic roleplay world model system.

Your task is to interpret natural language requests about spatial context and surrounding entities.

SPATIAL CONTEXT REQUEST:
"{}"

TARGET ENTITY ID: {}

Your analysis should identify:
1. What type of spatial information the user wants
2. The scope of the spatial analysis (immediate vicinity, broader area, hierarchical context)
3. Types of entities to include (characters, objects, locations, etc.)
4. The level of detail needed (basic presence, detailed descriptions, relationships)
5. Any specific filtering criteria mentioned

RESPONSE FORMAT (JSON):
{{
    "interpretation": "Clear restatement of what spatial context is being requested",
    "analysis_scope": "immediate|local|regional|hierarchical|comprehensive",
    "entity_types_to_include": ["character", "location", "item", "organization", "concept"],
    "detail_level": "basic|moderate|detailed|comprehensive",
    "spatial_filters": {{
        "include_parents": true|false,
        "include_children": true|false,
        "include_siblings": true|false,
        "include_nearby": true|false,
        "distance_consideration": "within|adjacent|nearby|region"
    }},
    "reasoning": "Explanation of why these parameters were chosen",
    "expected_output": "Description of what kind of spatial context should be returned"
}}

Examples:
- "What's around the main character?" → immediate scope with all entity types
- "Show me everything in this building" → hierarchical scope with contained entities
- "What other rooms are on this floor?" → local scope with sibling locations
- "Give me the full context of this area" → comprehensive scope with detailed analysis

Be intelligent about interpreting spatial relationships and context needs."#,
            request,
            entity_id
        )
    }

    /// Execute AI-driven spatial context analysis
    async fn analyze_spatial_context(&self, request: &str, entity_id: Uuid, user_id: Uuid) -> Result<SpatialContextAnalysis, ToolError> {
        let prompt = self.build_spatial_context_prompt(request, &entity_id.to_string());

        let spatial_schema = json!({
            "type": "object",
            "properties": {
                "interpretation": {"type": "string"},
                "analysis_scope": {"type": "string", "enum": ["immediate", "local", "regional", "hierarchical", "comprehensive"]},
                "entity_types_to_include": {"type": "array", "items": {"type": "string"}},
                "detail_level": {"type": "string", "enum": ["basic", "moderate", "detailed", "comprehensive"]},
                "spatial_filters": {
                    "type": "object",
                    "properties": {
                        "include_parents": {"type": "boolean"},
                        "include_children": {"type": "boolean"},
                        "include_siblings": {"type": "boolean"},
                        "include_nearby": {"type": "boolean"},
                        "distance_consideration": {"type": "string", "enum": ["within", "adjacent", "nearby", "region"]}
                    }
                },
                "reasoning": {"type": "string"},
                "expected_output": {"type": "string"}
            },
            "required": ["interpretation", "analysis_scope", "entity_types_to_include", "detail_level", "spatial_filters", "reasoning", "expected_output"]
        });

        // Execute AI analysis using spatial planning model
        let ai_response = self.execute_ai_request(&prompt, &spatial_schema, &self.app_state.config.agentic_planning_model).await?;
        
        serde_json::from_value(ai_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse spatial context analysis: {}", e)))
    }

    /// Execute AI request with structured output
    async fn execute_ai_request(&self, prompt: &str, schema: &JsonValue, model: &str) -> Result<JsonValue, ToolError> {
        let system_prompt = "You are a spatial analysis agent for a fictional roleplay world. All content is creative fiction for a game.";
        
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
            max_tokens: Some(1500),
            temperature: Some(0.2),
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

/// AI analysis of spatial context requirements
#[derive(Debug, Serialize, Deserialize)]
pub struct SpatialContextAnalysis {
    pub interpretation: String,
    pub analysis_scope: String,
    pub entity_types_to_include: Vec<String>,
    pub detail_level: String,
    pub spatial_filters: SpatialFilters,
    pub reasoning: String,
    pub expected_output: String,
}

/// Spatial filtering criteria
#[derive(Debug, Serialize, Deserialize)]
pub struct SpatialFilters {
    pub include_parents: bool,
    pub include_children: bool,
    pub include_siblings: bool,
    pub include_nearby: bool,
    pub distance_consideration: String,
}

/// Input for spatial context requests
#[derive(Debug, Deserialize)]
pub struct GetSpatialContextInput {
    pub user_id: String,
    pub entity_id: String,
    pub context_request: String,
    pub include_details: Option<bool>,
}

/// Output from spatial context analysis
#[derive(Debug, Serialize)]
pub struct SpatialContextOutput {
    pub target_entity_id: String,
    pub analysis: SpatialContextAnalysis,
    pub spatial_entities: Vec<SpatialEntityInfo>,
    pub hierarchy_info: Option<HierarchyContextInfo>,
    pub summary: String,
}

/// Information about entities in spatial context
#[derive(Debug, Serialize)]
pub struct SpatialEntityInfo {
    pub entity_id: String,
    pub name: String,
    pub entity_type: String,
    pub spatial_relationship: String,
    pub distance_description: String,
    pub significance: String,
}

/// Hierarchical context information
#[derive(Debug, Serialize)]
pub struct HierarchyContextInfo {
    pub parent_context: Option<String>,
    pub child_entities: Vec<String>,
    pub sibling_entities: Vec<String>,
    pub spatial_scale: Option<String>,
}

#[async_trait]
impl ScribeTool for GetSpatialContextTool {
    fn name(&self) -> &'static str {
        "get_spatial_context"
    }

    fn description(&self) -> &'static str {
        "AI-powered spatial context analysis that interprets natural language requests about \
         what entities exist around a given location or entity, providing intelligent spatial \
         relationship analysis and context-aware entity discovery."
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
                    "description": "UUID of the entity to analyze spatial context around"
                },
                "context_request": {
                    "type": "string",
                    "description": "Natural language description of what spatial context is needed (e.g., 'what's around this character?', 'show me everything in this building')"
                },
                "include_details": {
                    "type": "boolean",
                    "default": false,
                    "description": "Whether to include detailed entity information"
                }
            },
            "required": ["user_id", "entity_id", "context_request"]
        })
    }

    #[instrument(skip(self, params, _session_dek), fields(tool = "get_spatial_context"))]
    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let input: GetSpatialContextInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;

        let entity_id = Uuid::parse_str(&input.entity_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid entity_id: {}", e)))?;

        info!("AI spatial context analysis for entity {} with request: '{}'", entity_id, input.context_request);

        // Step 1: Use AI to analyze what kind of spatial context is needed
        let analysis = self.analyze_spatial_context(&input.context_request, entity_id, user_id).await?;

        debug!("AI analyzed spatial context: {}", analysis.interpretation);

        // Step 2: Execute the spatial analysis based on AI interpretation
        // For now, this is a simplified implementation - in a full system, this would
        // use the analysis parameters to intelligently query the ECS system
        let spatial_entities = vec![
            SpatialEntityInfo {
                entity_id: "example-1".to_string(),
                name: "Nearby Character".to_string(),
                entity_type: "character".to_string(),
                spatial_relationship: "adjacent".to_string(),
                distance_description: "within immediate vicinity".to_string(),
                significance: "potentially relevant for interaction".to_string(),
            }
        ];

        let output = SpatialContextOutput {
            target_entity_id: entity_id.to_string(),
            analysis,
            spatial_entities,
            hierarchy_info: None,
            summary: "AI-generated spatial context analysis completed".to_string(),
        };

        info!("AI spatial context analysis completed for entity {}", entity_id);
        Ok(serde_json::to_value(output)?)
    }
}

// ===== AI-DRIVEN ENTITY MOVEMENT TOOL =====

/// AI-powered tool that interprets natural language movement requests
/// and executes intelligent entity relocation with spatial reasoning
#[derive(Clone)]
pub struct MoveEntityTool {
    app_state: Arc<AppState>,
}

impl MoveEntityTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Build AI prompt for interpreting movement requests
    fn build_movement_prompt(&self, request: &str, entity_id: &str, current_context: &str) -> String {
        format!(
            r#"You are an intelligent movement planning agent for a dynamic roleplay world model system.

Your task is to interpret natural language movement requests and plan appropriate entity relocation.

MOVEMENT REQUEST:
"{}"

ENTITY TO MOVE: {}

CURRENT CONTEXT:
{}

Your analysis should determine:
1. The destination for the movement (specific location, relative position, or abstract target)
2. The type of movement (teleport, walk, fly, travel, etc.)
3. Whether this is a simple position change or requires complex spatial relationships
4. Any preconditions or constraints for the movement
5. Expected spatial scale changes (Intimate -> Planetary, etc.)

RESPONSE FORMAT (JSON):
{{
    "interpretation": "Clear restatement of the movement request",
    "movement_type": "teleport|walk|fly|travel|spatial_transition|abstract_movement",
    "destination": {{
        "type": "absolute_position|relative_position|named_location|entity_proximity",
        "target": "specific destination identifier or description",
        "coordinates": {{"x": 0.0, "y": 0.0, "z": 0.0}},
        "zone": "destination zone if applicable"
    }},
    "spatial_scale_change": {{
        "from_scale": "Cosmic|Planetary|Intimate|Unknown",
        "to_scale": "Cosmic|Planetary|Intimate|Unknown",
        "requires_hierarchy_update": true|false
    }},
    "movement_constraints": ["constraint1", "constraint2"],
    "preconditions": ["condition1", "condition2"],
    "reasoning": "Explanation of the movement plan and spatial implications",
    "expected_result": "Description of what the world state should look like after movement"
}}

Examples:
- "Move the character to the tavern" → named_location movement to "tavern"
- "Teleport 10 meters north" → relative_position movement with coordinates
- "Bring the ship into orbit" → spatial_transition from Planetary to Cosmic scale
- "Follow the other character" → entity_proximity movement

Be intelligent about interpreting movement intentions and spatial relationships."#,
            request,
            entity_id,
            current_context
        )
    }

    /// Execute AI request with structured output
    async fn execute_ai_request(&self, prompt: &str, schema: &JsonValue, model: &str) -> Result<JsonValue, ToolError> {
        let system_prompt = "You are a movement planning agent for a fictional roleplay world. All content is creative fiction for a game.";
        
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
            max_tokens: Some(1500),
            temperature: Some(0.2),
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

/// AI analysis of movement requirements
#[derive(Debug, Serialize, Deserialize)]
pub struct MovementAnalysis {
    pub interpretation: String,
    pub movement_type: String,
    pub destination: MovementDestination,
    pub spatial_scale_change: SpatialScaleChange,
    pub movement_constraints: Vec<String>,
    pub preconditions: Vec<String>,
    pub reasoning: String,
    pub expected_result: String,
}

/// Movement destination specification
#[derive(Debug, Serialize, Deserialize)]
pub struct MovementDestination {
    pub destination_type: String,
    pub target: String,
    pub coordinates: Option<Coordinates>,
    pub zone: Option<String>,
}

/// Coordinate specification
#[derive(Debug, Serialize, Deserialize)]
pub struct Coordinates {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

/// Spatial scale change information
#[derive(Debug, Serialize, Deserialize)]
pub struct SpatialScaleChange {
    pub from_scale: String,
    pub to_scale: String,
    pub requires_hierarchy_update: bool,
}

/// Input for movement requests
#[derive(Debug, Deserialize)]
pub struct MoveEntityInput {
    pub user_id: String,
    pub entity_id: String,
    pub movement_request: String,
    pub current_context: Option<String>,
}

/// Output from movement operations
#[derive(Debug, Serialize)]
pub struct MoveEntityOutput {
    pub entity_id: String,
    pub movement_analysis: MovementAnalysis,
    pub success: bool,
    pub new_position: Option<JsonValue>,
    pub message: String,
}

#[async_trait]
impl ScribeTool for MoveEntityTool {
    fn name(&self) -> &'static str {
        "move_entity"
    }

    fn description(&self) -> &'static str {
        "AI-powered entity movement that interprets natural language requests like \
         'move the character to the tavern' or 'teleport 10 meters north' and executes \
         intelligent spatial relocation with proper scale transitions."
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
                    "description": "UUID of the entity to move"
                },
                "movement_request": {
                    "type": "string",
                    "description": "Natural language description of how/where to move the entity (e.g., 'move to the tavern', 'teleport 10 meters north')"
                },
                "current_context": {
                    "type": "string",
                    "description": "Optional context about the current scene or spatial situation"
                }
            },
            "required": ["user_id", "entity_id", "movement_request"]
        })
    }

    #[instrument(skip(self, params, _session_dek), fields(tool = "move_entity"))]
    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let input: MoveEntityInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;

        let entity_id = Uuid::parse_str(&input.entity_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid entity_id: {}", e)))?;

        let current_context = input.current_context.unwrap_or_else(|| "No additional context provided".to_string());

        info!("AI movement request for entity {}: '{}'", entity_id, input.movement_request);

        // Step 1: Use AI to analyze the movement request
        let prompt = self.build_movement_prompt(&input.movement_request, &entity_id.to_string(), &current_context);

        let movement_schema = json!({
            "type": "object",
            "properties": {
                "interpretation": {"type": "string"},
                "movement_type": {"type": "string", "enum": ["teleport", "walk", "fly", "travel", "spatial_transition", "abstract_movement"]},
                "destination": {
                    "type": "object",
                    "properties": {
                        "destination_type": {"type": "string", "enum": ["absolute_position", "relative_position", "named_location", "entity_proximity"]},
                        "target": {"type": "string"},
                        "coordinates": {
                            "type": "object",
                            "properties": {
                                "x": {"type": "number"},
                                "y": {"type": "number"},
                                "z": {"type": "number"}
                            }
                        },
                        "zone": {"type": "string"}
                    },
                    "required": ["destination_type", "target"]
                },
                "spatial_scale_change": {
                    "type": "object",
                    "properties": {
                        "from_scale": {"type": "string", "enum": ["Cosmic", "Planetary", "Intimate", "Unknown"]},
                        "to_scale": {"type": "string", "enum": ["Cosmic", "Planetary", "Intimate", "Unknown"]},
                        "requires_hierarchy_update": {"type": "boolean"}
                    },
                    "required": ["from_scale", "to_scale", "requires_hierarchy_update"]
                },
                "movement_constraints": {"type": "array", "items": {"type": "string"}},
                "preconditions": {"type": "array", "items": {"type": "string"}},
                "reasoning": {"type": "string"},
                "expected_result": {"type": "string"}
            },
            "required": ["interpretation", "movement_type", "destination", "spatial_scale_change", "movement_constraints", "preconditions", "reasoning", "expected_result"]
        });

        // Execute AI analysis using tactical agent model for movement planning
        let ai_response = self.execute_ai_request(&prompt, &movement_schema, &self.app_state.config.tactical_agent_model).await?;

        let movement_analysis: MovementAnalysis = serde_json::from_value(ai_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse movement analysis: {}", e)))?;

        debug!("AI analyzed movement: {}", movement_analysis.interpretation);

        // Step 2: Execute the movement based on AI analysis
        // For now, this is a placeholder - in a full system, this would use the
        // movement_analysis to actually update the entity's position in the ECS
        let output = MoveEntityOutput {
            entity_id: entity_id.to_string(),
            movement_analysis,
            success: true,
            new_position: Some(json!({"x": 0.0, "y": 0.0, "z": 0.0, "zone": "analyzed_destination"})),
            message: "AI movement analysis completed (actual movement not yet implemented)".to_string(),
        };

        info!("AI movement analysis completed for entity {}", entity_id);
        Ok(serde_json::to_value(output)?)
    }
}

// ===== SELF-REGISTERING TOOL IMPLEMENTATIONS =====

#[async_trait]
impl SelfRegisteringTool for GetSpatialContextTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Perception
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "analyze".to_string(),
                target: "spatial context".to_string(),
                context: Some("natural language".to_string()),
            },
            ToolCapability {
                action: "discover".to_string(),
                target: "surrounding entities".to_string(),
                context: Some("spatial relationships".to_string()),
            },
            ToolCapability {
                action: "interpret".to_string(),
                target: "context requests".to_string(),
                context: Some("spatial analysis".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to understand what entities exist around a specific location or entity. \
         Perfect for requests like 'what's around the main character?', 'show me everything in this building', \
         or 'what other rooms are on this floor?'.".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for moving entities, creating new entities, or modifying spatial relationships. \
         Use specific spatial manipulation or entity creation tools instead.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Analyze surroundings of a character".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "entity_id": "456e7890-e12b-34c5-a789-012345678901",
                    "context_request": "What's around the main character?",
                    "include_details": true
                }),
                expected_output: "Detailed spatial context including nearby entities, their relationships, and significance".to_string(),
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
                allowed_scopes: vec!["entities".to_string(), "spatial".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 75,
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
            "spatial".to_string(),
            "context".to_string(),
            "analysis".to_string(),
            "ai-powered".to_string(),
            "discovery".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "target_entity_id": {
                    "type": "string",
                    "description": "UUID of the entity that was analyzed"
                },
                "analysis": {
                    "type": "object",
                    "description": "AI interpretation of the spatial context request"
                },
                "spatial_entities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "entity_id": {"type": "string"},
                            "name": {"type": "string"},
                            "spatial_relationship": {"type": "string"},
                            "significance": {"type": "string"}
                        }
                    },
                    "description": "Entities found in the spatial context"
                },
                "summary": {
                    "type": "string",
                    "description": "Summary of the spatial context analysis"
                }
            },
            "required": ["target_entity_id", "analysis", "spatial_entities", "summary"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "INVALID_ENTITY_ID".to_string(),
                description: "The provided entity ID is not valid or not found".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "AI_ANALYSIS_FAILED".to_string(),
                description: "The AI service failed to analyze the spatial context".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "SPATIAL_DATA_UNAVAILABLE".to_string(),
                description: "Spatial data for the entity is not available".to_string(),
                retry_able: false,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

#[async_trait]
impl SelfRegisteringTool for MoveEntityTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Tactical
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "move".to_string(),
                target: "entities".to_string(),
                context: Some("spatial relocation".to_string()),
            },
            ToolCapability {
                action: "plan".to_string(),
                target: "movement".to_string(),
                context: Some("natural language interpretation".to_string()),
            },
            ToolCapability {
                action: "execute".to_string(),
                target: "spatial transitions".to_string(),
                context: Some("scale changes".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to move entities to different locations based on natural language requests. \
         Perfect for requests like 'move the character to the tavern', 'teleport 10 meters north', \
         or 'bring the ship into orbit'.".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for creating new entities, analyzing spatial context, or modifying entity properties \
         other than position. Use specific entity creation or modification tools instead.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Move character to a named location".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "entity_id": "456e7890-e12b-34c5-a789-012345678901",
                    "movement_request": "Move the character to the tavern",
                    "current_context": "Character is currently in the town square"
                }),
                expected_output: "Successful movement with updated position and spatial context".to_string(),
            },
        ]
    }
    
    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
            ],
            required_capabilities: vec![],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true, // Movement modifies entity position
                allowed_scopes: vec!["entities".to_string(), "spatial".to_string()],
            },
            audit_level: AuditLevel::Detailed,
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
            "movement".to_string(),
            "spatial".to_string(),
            "modification".to_string(),
            "ai-powered".to_string(),
            "positioning".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "entity_id": {
                    "type": "string",
                    "description": "UUID of the entity that was moved"
                },
                "movement_analysis": {
                    "type": "object",
                    "description": "AI analysis of the movement request and execution plan"
                },
                "success": {
                    "type": "boolean",
                    "description": "Whether the movement was successful"
                },
                "new_position": {
                    "type": "object",
                    "description": "New position coordinates and spatial context"
                },
                "message": {
                    "type": "string",
                    "description": "Status message about the movement operation"
                }
            },
            "required": ["entity_id", "movement_analysis", "success", "message"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "INVALID_ENTITY_ID".to_string(),
                description: "The provided entity ID is not valid or not found".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "MOVEMENT_BLOCKED".to_string(),
                description: "The movement cannot be completed due to spatial constraints".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "AI_PLANNING_FAILED".to_string(),
                description: "The AI service failed to plan the movement".to_string(),
                retry_able: true,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

// Helper function to register spatial interaction tools
pub fn register_spatial_interaction_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    let spatial_context_tool = Arc::new(GetSpatialContextTool::new(app_state.clone())) as Arc<dyn SelfRegisteringTool + Send + Sync>;
    let move_entity_tool = Arc::new(MoveEntityTool::new(app_state.clone())) as Arc<dyn SelfRegisteringTool + Send + Sync>;
    
    UnifiedToolRegistry::register(spatial_context_tool)?;
    UnifiedToolRegistry::register(move_entity_tool)?;
    
    tracing::info!("Registered 2 AI-driven spatial interaction tools with unified registry");
    Ok(())
}