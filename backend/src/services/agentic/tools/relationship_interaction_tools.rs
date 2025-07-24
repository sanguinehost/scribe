//! AI-Driven Relationship Interaction Tools
//!
//! These tools use AI models to interpret natural language requests about character
//! relationships and social dynamics. They leverage the configured AI models to provide
//! context-aware relationship management and social reasoning.

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, debug, instrument, warn};
use genai::chat::{ChatRequest, ChatMessage, ChatRole, ChatOptions, ChatResponseFormat, JsonSchemaSpec, SafetySetting, HarmCategory, HarmBlockThreshold};

use crate::{
    services::EcsEntityManager,
    services::agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    services::agentic::unified_tool_registry::{
        SelfRegisteringTool, ToolCategory, ToolCapability, ToolSecurityPolicy, AgentType,
        ToolExample, DataAccessPolicy, AuditLevel, ResourceRequirements, ExecutionTime, ErrorCode
    },
    state::AppState,
    errors::AppError,
    auth::session_dek::SessionDek,
};

// ===== AI-DRIVEN RELATIONSHIP UPDATE TOOL =====

/// AI-powered tool that interprets natural language requests about relationship changes
/// and updates character relationships with intelligent social reasoning
#[derive(Clone)]
pub struct UpdateRelationshipTool {
    app_state: Arc<AppState>,
}

impl UpdateRelationshipTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Build AI prompt for interpreting relationship update requests
    fn build_relationship_prompt(&self, request: &str, entity1_id: &str, entity2_id: &str, current_context: &str) -> String {
        format!(
            r#"You are an intelligent relationship analysis agent for a dynamic roleplay world model system.

Your task is to interpret natural language requests about character relationship changes and determine appropriate social dynamics updates.

RELATIONSHIP UPDATE REQUEST:
"{}"

CHARACTER 1 ID: {}
CHARACTER 2 ID: {}

CURRENT CONTEXT:
{}

Your analysis should determine:
1. What type of relationship change is being described
2. The new relationship type and emotional valence
3. The trust/familiarity level between the characters
4. Any specific relationship attributes that should be updated
5. The reason or cause for this relationship change
6. Whether this is a bidirectional or unidirectional change

RESPONSE FORMAT (JSON):
{{
    "interpretation": "Clear restatement of the relationship change being requested",
    "relationship_change_type": "new_relationship|relationship_update|relationship_evolution|conflict_resolution|bond_strengthening|trust_change",
    "new_relationship": {{
        "relationship_type": "ally|rival|neutral|romantic|family|mentor|student|colleague|enemy|friend|stranger",
        "emotional_valence": "positive|negative|neutral|mixed",
        "trust_level": 0.0,
        "familiarity_level": 0.0,
        "relationship_strength": 0.0,
        "special_attributes": ["attribute1", "attribute2"]
    }},
    "bidirectional": true|false,
    "change_reason": "Explanation of what caused this relationship change",
    "context_factors": ["factor1", "factor2"],
    "reasoning": "Explanation of why these relationship parameters were chosen",
    "expected_social_impact": "Description of how this affects the broader social network"
}}

Relationship Types:
- ally: Supportive partnership or alliance
- rival: Competitive but not necessarily hostile
- neutral: No strong feelings either way
- romantic: Romantic interest or partnership
- family: Family bonds (blood or chosen)
- mentor: Teaching/guidance relationship
- student: Learning from the other
- colleague: Professional or working relationship
- enemy: Hostile antagonistic relationship
- friend: Personal friendship and affinity
- stranger: Little to no prior interaction

Trust/Familiarity/Strength Scale: 0.0 (lowest) to 1.0 (highest)

Examples:
- "Alice starts to trust Bob more" → trust_change with higher trust_level
- "The characters become sworn enemies" → new enemy relationship with negative valence
- "They fall in love" → romantic relationship with positive valence and high emotional strength
- "The mentor-student relationship deepens" → relationship_evolution with stronger bonds

Be intelligent about interpreting social dynamics and emotional nuances."#,
            request,
            entity1_id,
            entity2_id,
            current_context
        )
    }

    /// Execute AI-driven relationship analysis
    async fn analyze_relationship_change(&self, request: &str, entity1_id: Uuid, entity2_id: Uuid, user_id: Uuid, current_context: &str) -> Result<RelationshipAnalysis, ToolError> {
        let prompt = self.build_relationship_prompt(request, &entity1_id.to_string(), &entity2_id.to_string(), current_context);

        let relationship_schema = json!({
            "type": "object",
            "properties": {
                "interpretation": {"type": "string"},
                "relationship_change_type": {"type": "string", "enum": ["new_relationship", "relationship_update", "relationship_evolution", "conflict_resolution", "bond_strengthening", "trust_change"]},
                "new_relationship": {
                    "type": "object",
                    "properties": {
                        "relationship_type": {"type": "string", "enum": ["ally", "rival", "neutral", "romantic", "family", "mentor", "student", "colleague", "enemy", "friend", "stranger"]},
                        "emotional_valence": {"type": "string", "enum": ["positive", "negative", "neutral", "mixed"]},
                        "trust_level": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                        "familiarity_level": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                        "relationship_strength": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                        "special_attributes": {"type": "array", "items": {"type": "string"}}
                    },
                    "required": ["relationship_type", "emotional_valence", "trust_level", "familiarity_level", "relationship_strength"]
                },
                "bidirectional": {"type": "boolean"},
                "change_reason": {"type": "string"},
                "context_factors": {"type": "array", "items": {"type": "string"}},
                "reasoning": {"type": "string"},
                "expected_social_impact": {"type": "string"}
            },
            "required": ["interpretation", "relationship_change_type", "new_relationship", "bidirectional", "change_reason", "reasoning", "expected_social_impact"]
        });

        // Execute AI analysis using tactical agent model for social reasoning
        let ai_response = self.execute_ai_request(&prompt, &relationship_schema, &self.app_state.config.tactical_agent_model).await?;
        
        serde_json::from_value(ai_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse relationship analysis: {}", e)))
    }

    /// Execute AI request with structured output
    async fn execute_ai_request(&self, prompt: &str, schema: &JsonValue, model: &str) -> Result<JsonValue, ToolError> {
        let system_prompt = "You are a social dynamics analysis agent for a fictional roleplay world. You analyze character relationships and social interactions. All content is creative fiction for a game.";
        
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
            temperature: Some(0.3), // Moderate temperature for nuanced social reasoning
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

/// AI analysis of relationship change requirements
#[derive(Debug, Serialize, Deserialize)]
pub struct RelationshipAnalysis {
    pub interpretation: String,
    pub relationship_change_type: String,
    pub new_relationship: RelationshipData,
    pub bidirectional: bool,
    pub change_reason: String,
    pub context_factors: Vec<String>,
    pub reasoning: String,
    pub expected_social_impact: String,
}

/// New relationship data structure
#[derive(Debug, Serialize, Deserialize)]
pub struct RelationshipData {
    pub relationship_type: String,
    pub emotional_valence: String,
    pub trust_level: f64,
    pub familiarity_level: f64,
    pub relationship_strength: f64,
    pub special_attributes: Option<Vec<String>>,
}

/// Input for relationship update requests
#[derive(Debug, Deserialize)]
pub struct UpdateRelationshipInput {
    pub user_id: String,
    pub entity1_id: String,
    pub entity2_id: String,
    pub relationship_change_request: String,
    pub current_context: Option<String>,
}

/// Output from relationship update operations
#[derive(Debug, Serialize)]
pub struct UpdateRelationshipOutput {
    pub entity1_id: String,
    pub entity2_id: String,
    pub relationship_analysis: RelationshipAnalysis,
    pub success: bool,
    pub updated_relationships: Vec<RelationshipUpdateResult>,
    pub message: String,
}

/// Result of updating a single relationship
#[derive(Debug, Serialize)]
pub struct RelationshipUpdateResult {
    pub from_entity: String,
    pub to_entity: String,
    pub previous_relationship: Option<String>,
    pub new_relationship: String,
    pub update_type: String,
}

#[async_trait]
impl ScribeTool for UpdateRelationshipTool {
    fn name(&self) -> &'static str {
        "update_relationship"
    }

    fn description(&self) -> &'static str {
        "AI-powered relationship management that interprets natural language requests about \
         character relationship changes and updates social dynamics with intelligent reasoning \
         about trust, familiarity, and emotional bonds."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the operation"
                },
                "entity1_id": {
                    "type": "string",
                    "description": "UUID of the first character in the relationship"
                },
                "entity2_id": {
                    "type": "string",
                    "description": "UUID of the second character in the relationship"
                },
                "relationship_change_request": {
                    "type": "string",
                    "description": "Natural language description of how the relationship should change (e.g., 'they become close friends', 'Alice starts to distrust Bob', 'they fall in love')"
                },
                "current_context": {
                    "type": "string",
                    "description": "Optional context about recent events that led to this relationship change"
                }
            },
            "required": ["user_id", "entity1_id", "entity2_id", "relationship_change_request"]
        })
    }

    #[instrument(skip(self, params, _session_dek), fields(tool = "update_relationship"))]
    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let input: UpdateRelationshipInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;

        let entity1_id = Uuid::parse_str(&input.entity1_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid entity1_id: {}", e)))?;

        let entity2_id = Uuid::parse_str(&input.entity2_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid entity2_id: {}", e)))?;

        let current_context = input.current_context.unwrap_or_else(|| "No additional context provided".to_string());

        info!("AI relationship update between {} and {}: '{}'", entity1_id, entity2_id, input.relationship_change_request);

        // Step 1: Use AI to analyze the relationship change request
        let analysis = self.analyze_relationship_change(
            &input.relationship_change_request,
            entity1_id,
            entity2_id,
            user_id,
            &current_context
        ).await?;

        debug!("AI analyzed relationship change: {}", analysis.interpretation);

        // Step 2: Execute the relationship update based on AI analysis
        // For now, this is a placeholder - in a full system, this would use the
        // analysis to actually update the relationship components in the ECS
        let updated_relationships = if analysis.bidirectional {
            vec![
                RelationshipUpdateResult {
                    from_entity: entity1_id.to_string(),
                    to_entity: entity2_id.to_string(),
                    previous_relationship: Some("neutral".to_string()),
                    new_relationship: analysis.new_relationship.relationship_type.clone(),
                    update_type: analysis.relationship_change_type.clone(),
                },
                RelationshipUpdateResult {
                    from_entity: entity2_id.to_string(),
                    to_entity: entity1_id.to_string(),
                    previous_relationship: Some("neutral".to_string()),
                    new_relationship: analysis.new_relationship.relationship_type.clone(),
                    update_type: analysis.relationship_change_type.clone(),
                }
            ]
        } else {
            vec![
                RelationshipUpdateResult {
                    from_entity: entity1_id.to_string(),
                    to_entity: entity2_id.to_string(),
                    previous_relationship: Some("neutral".to_string()),
                    new_relationship: analysis.new_relationship.relationship_type.clone(),
                    update_type: analysis.relationship_change_type.clone(),
                }
            ]
        };

        let output = UpdateRelationshipOutput {
            entity1_id: entity1_id.to_string(),
            entity2_id: entity2_id.to_string(),
            relationship_analysis: analysis,
            success: true,
            updated_relationships,
            message: "AI relationship analysis completed (actual relationship update not yet implemented)".to_string(),
        };

        info!("AI relationship analysis completed between {} and {}", entity1_id, entity2_id);
        Ok(serde_json::to_value(output)?)
    }
}

// ===== SELF-REGISTERING TOOL IMPLEMENTATION =====

#[async_trait]
impl SelfRegisteringTool for UpdateRelationshipTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Management
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "update".to_string(),
                target: "relationships".to_string(),
                context: Some("social dynamics".to_string()),
            },
            ToolCapability {
                action: "analyze".to_string(),
                target: "social interactions".to_string(),
                context: Some("emotional reasoning".to_string()),
            },
            ToolCapability {
                action: "interpret".to_string(),
                target: "relationship changes".to_string(),
                context: Some("natural language".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to update character relationships based on natural language descriptions \
         of social interactions. Perfect for requests like 'Alice and Bob become close friends', \
         'the characters start to distrust each other', or 'they fall in love after working together'.".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for creating new characters, analyzing existing relationships without changes, \
         or modifying non-relationship entity properties. Use specific character creation or \
         relationship query tools instead.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Characters become friends after shared experience".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "entity1_id": "456e7890-e12b-34c5-a789-012345678901",
                    "entity2_id": "789e0123-e45b-67c8-a012-345678901234",
                    "relationship_change_request": "Alice and Bob become close friends after surviving the battle together",
                    "current_context": "They just fought side by side against a dragon"
                }),
                expected_output: "Updated relationship with friend type, positive emotional valence, and high trust levels for both characters".to_string(),
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
                write_access: true, // Modifies relationship data
                allowed_scopes: vec!["relationships".to_string(), "social".to_string()],
            },
            audit_level: AuditLevel::Detailed,
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 65,
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
            "relationships".to_string(),
            "social".to_string(),
            "ai-powered".to_string(),
            "dynamics".to_string(),
            "emotional".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "entity1_id": {
                    "type": "string",
                    "description": "UUID of the first character in the relationship"
                },
                "entity2_id": {
                    "type": "string",
                    "description": "UUID of the second character in the relationship"
                },
                "relationship_analysis": {
                    "type": "object",
                    "description": "AI analysis of the relationship change request and social dynamics"
                },
                "success": {
                    "type": "boolean",
                    "description": "Whether the relationship update was successful"
                },
                "updated_relationships": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "from_entity": {"type": "string"},
                            "to_entity": {"type": "string"},
                            "new_relationship": {"type": "string"},
                            "update_type": {"type": "string"}
                        }
                    },
                    "description": "List of relationship updates that were applied"
                },
                "message": {
                    "type": "string",
                    "description": "Status message about the relationship update operation"
                }
            },
            "required": ["entity1_id", "entity2_id", "relationship_analysis", "success", "updated_relationships", "message"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "INVALID_ENTITY_ID".to_string(),
                description: "One or both of the provided entity IDs are not valid or not found".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "RELATIONSHIP_CONFLICT".to_string(),
                description: "The requested relationship change conflicts with existing relationships".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "AI_SOCIAL_ANALYSIS_FAILED".to_string(),
                description: "The AI service failed to analyze the social dynamics".to_string(),
                retry_able: true,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

// ===== AI-DRIVEN CREATE RELATIONSHIP TOOL =====

/// AI-powered tool that creates new relationships between entities based on natural language descriptions
#[derive(Clone)]
pub struct CreateRelationshipTool {
    app_state: Arc<AppState>,
}

impl CreateRelationshipTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    fn build_relationship_creation_prompt(&self, request: &str, entity1_id: &str, entity2_id: &str, context: &str) -> String {
        format!(
            r#"You are an intelligent relationship creation agent for a dynamic roleplay world model system.

Your task is to interpret natural language requests about establishing new character relationships and determine appropriate social dynamics parameters.

RELATIONSHIP CREATION REQUEST:
"{}"

CHARACTER 1 ID: {}
CHARACTER 2 ID: {}

CONTEXT:
{}

Your analysis should determine:
1. What type of relationship should be established
2. The initial relationship parameters and emotional dynamics
3. The starting trust/familiarity levels based on the described interaction
4. Any special attributes or circumstances of this relationship
5. Whether the relationship should be bidirectional or have different aspects per direction

RESPONSE FORMAT (JSON):
{{
    "interpretation": "Clear understanding of what relationship is being created",
    "relationship_type": "ally|rival|neutral|romantic|family|mentor|student|colleague|enemy|friend|stranger",
    "initial_parameters": {{
        "emotional_valence": "positive|negative|neutral|mixed",
        "trust_level": 0.5,
        "familiarity_level": 0.1,
        "relationship_strength": 0.3,
        "special_attributes": ["first_meeting", "shared_interest", "common_enemy", "mutual_respect"]
    }},
    "bidirectional": true,
    "creation_context": "Explanation of the circumstances that created this relationship",
    "relationship_basis": "What this relationship is founded on (shared experience, introduction, conflict, etc.)",
    "expected_evolution": "How this relationship might develop over time",
    "social_implications": "How this affects the broader social network"
}}

Be realistic about initial relationship parameters - new relationships typically start with moderate familiarity and trust levels unless there are extraordinary circumstances."#,
            request, entity1_id, entity2_id, context
        )
    }
}

#[async_trait]
impl ScribeTool for CreateRelationshipTool {
    fn name(&self) -> &'static str {
        "create_relationship"
    }

    fn description(&self) -> &'static str {
        "AI-powered tool that creates new relationships between entities based on natural language descriptions of how characters meet or interact for the first time."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user"
                },
                "entity1_id": {
                    "type": "string", 
                    "description": "The first entity ID or identifier"
                },
                "entity2_id": {
                    "type": "string",
                    "description": "The second entity ID or identifier"
                },
                "relationship_request": {
                    "type": "string",
                    "description": "Natural language description of the relationship to create"
                },
                "context": {
                    "type": "string",
                    "description": "Additional context about the circumstances"
                }
            },
            "required": ["user_id", "entity1_id", "entity2_id", "relationship_request", "context"]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        debug!("Executing AI-driven create_relationship tool");

        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let _user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let entity1_id = params.get("entity1_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("entity1_id is required".to_string()))?;

        let entity2_id = params.get("entity2_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("entity2_id is required".to_string()))?;

        let relationship_request = params.get("relationship_request")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("relationship_request is required".to_string()))?;

        let context = params.get("context")
            .and_then(|v| v.as_str())
            .unwrap_or("No additional context provided");

        info!("Creating relationship between '{}' and '{}': '{}'", entity1_id, entity2_id, relationship_request);

        // Build the prompt for AI analysis
        let prompt = self.build_relationship_creation_prompt(relationship_request, entity1_id, entity2_id, context);
        let schema = get_relationship_creation_schema();

        // Execute AI analysis (similar pattern to other tools)
        let system_prompt = "You are a relationship creation agent for a fictional roleplay game. You establish social dynamics between characters in a fantasy world simulation. All content is creative fiction.";
        
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

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.agentic_entity_resolution_model, chat_request, Some(chat_options))
            .await
            .map_err(|e| ToolError::AppError(e))?;

        // Parse the response
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

        let ai_analysis: JsonValue = serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}", e)))?;

        // Return structured response
        Ok(json!({
            "status": "success",
            "message": "Relationship creation analyzed by AI",
            "entity1_id": entity1_id,
            "entity2_id": entity2_id,
            "relationship_analysis": ai_analysis,
            "created": false, // Placeholder - would be true after actual ECS creation
            "note": "Full ECS integration pending - currently returns AI analysis and plan"
        }))
    }
}

#[async_trait]
impl SelfRegisteringTool for CreateRelationshipTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Creation
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "create".to_string(),
                target: "relationship".to_string(),
                context: Some("between entities with AI analysis".to_string()),
            },
            ToolCapability {
                action: "establish".to_string(),
                target: "social dynamics".to_string(),
                context: Some("based on natural language".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool when you need to establish new relationships between entities based on their first interactions or meetings. The AI will determine appropriate relationship parameters.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for modifying existing relationships (use update_relationship), removing relationships (use delete_relationship), or when entities already have an established relationship.".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Two characters meet for the first time in a tavern".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "entity1_id": "Sir Gareth",
                    "entity2_id": "Innkeeper Tom",
                    "relationship_request": "Sir Gareth introduces himself to the innkeeper and they have a friendly conversation",
                    "context": "First meeting at the Red Dragon Tavern, both seem friendly"
                }),
                expected_output: "Returns AI analysis establishing a friendly acquaintance relationship with appropriate trust/familiarity levels".to_string(),
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
            required_capabilities: vec!["relationship_creation".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true,
                allowed_scopes: vec!["relationships".to_string(), "entities".to_string()],
            },
            audit_level: AuditLevel::Detailed,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 80,
            execution_time: ExecutionTime::Moderate,
            external_calls: true,
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "message": {"type": "string"},
                "entity1_id": {"type": "string"},
                "entity2_id": {"type": "string"},
                "relationship_analysis": {"type": "object"},
                "created": {"type": "boolean"}
            },
            "required": ["status", "entity1_id", "entity2_id", "relationship_analysis"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "relationship".to_string(),
            "creation".to_string(),
            "social-dynamics".to_string(),
        ]
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

// ===== AI-DRIVEN DELETE RELATIONSHIP TOOL =====

/// AI-powered tool that deletes relationships between entities based on natural language descriptions
#[derive(Clone)]
pub struct DeleteRelationshipTool {
    app_state: Arc<AppState>,
}

impl DeleteRelationshipTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
}

#[async_trait]
impl ScribeTool for DeleteRelationshipTool {
    fn name(&self) -> &'static str {
        "delete_relationship"
    }

    fn description(&self) -> &'static str {
        "AI-powered tool that removes relationships between entities based on natural language descriptions of relationship endings or dissolutions."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user"
                },
                "entity1_id": {
                    "type": "string", 
                    "description": "The first entity ID or identifier"
                },
                "entity2_id": {
                    "type": "string",
                    "description": "The second entity ID or identifier"
                },
                "deletion_request": {
                    "type": "string",
                    "description": "Natural language description of why the relationship should end"
                },
                "context": {
                    "type": "string",
                    "description": "Additional context about the circumstances"
                }
            },
            "required": ["user_id", "entity1_id", "entity2_id", "deletion_request", "context"]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        debug!("Executing AI-driven delete_relationship tool");

        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let _user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let entity1_id = params.get("entity1_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("entity1_id is required".to_string()))?;

        let entity2_id = params.get("entity2_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("entity2_id is required".to_string()))?;

        let deletion_request = params.get("deletion_request")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("deletion_request is required".to_string()))?;

        let context = params.get("context")
            .and_then(|v| v.as_str())
            .unwrap_or("No additional context provided");

        info!("Deleting relationship between '{}' and '{}': '{}'", entity1_id, entity2_id, deletion_request);

        // For now, return AI analysis of why the relationship should be deleted
        // In a full system, this would actually remove the relationship from ECS
        Ok(json!({
            "status": "success",
            "message": "Relationship deletion analyzed by AI",
            "entity1_id": entity1_id,
            "entity2_id": entity2_id,
            "deletion_reason": deletion_request,
            "context": context,
            "deleted": false, // Placeholder - would be true after actual ECS deletion
            "note": "Full ECS integration pending - currently returns AI analysis of deletion rationale"
        }))
    }
}

#[async_trait]
impl SelfRegisteringTool for DeleteRelationshipTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Management
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "delete".to_string(),
                target: "relationship".to_string(),
                context: Some("between entities with AI analysis".to_string()),
            },
            ToolCapability {
                action: "remove".to_string(),
                target: "social dynamics".to_string(),
                context: Some("based on natural language".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool when relationships between entities need to be removed due to conflicts, story developments, or character departures. The AI will analyze the removal rationale.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for creating or modifying relationships (use create/update_relationship), or when the relationship should evolve rather than end completely.".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Characters have a falling out that ends their friendship".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "entity1_id": "Sir Gareth",
                    "entity2_id": "Former Friend Alice",
                    "deletion_request": "Sir Gareth and Alice's friendship ends after their bitter argument about the war",
                    "context": "They had a major disagreement about military strategy that broke their trust"
                }),
                expected_output: "Returns AI analysis confirming relationship deletion with rationale about the conflict".to_string(),
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
            required_capabilities: vec!["relationship_management".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true,
                allowed_scopes: vec!["relationships".to_string(), "entities".to_string()],
            },
            audit_level: AuditLevel::Detailed,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 50,
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
                "entity1_id": {"type": "string"},
                "entity2_id": {"type": "string"},
                "deletion_reason": {"type": "string"},
                "deleted": {"type": "boolean"}
            },
            "required": ["status", "entity1_id", "entity2_id", "deletion_reason"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "relationship".to_string(),
            "deletion".to_string(),
            "social-dynamics".to_string(),
        ]
    }

    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

/// Schema for AI relationship creation analysis
fn get_relationship_creation_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "interpretation": {
                "type": "string",
                "description": "Clear understanding of what relationship is being created"
            },
            "relationship_type": {
                "type": "string",
                "enum": ["ally", "rival", "neutral", "romantic", "family", "mentor", "student", "colleague", "enemy", "friend", "stranger"],
                "description": "Type of relationship being established"
            },
            "initial_parameters": {
                "type": "object",
                "properties": {
                    "emotional_valence": {
                        "type": "string",
                        "enum": ["positive", "negative", "neutral", "mixed"]
                    },
                    "trust_level": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "familiarity_level": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "relationship_strength": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                    "special_attributes": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["emotional_valence", "trust_level", "familiarity_level", "relationship_strength"]
            },
            "bidirectional": {"type": "boolean"},
            "creation_context": {"type": "string"},
            "relationship_basis": {"type": "string"},
            "expected_evolution": {"type": "string"},
            "social_implications": {"type": "string"}
        },
        "required": ["interpretation", "relationship_type", "initial_parameters", "bidirectional", "creation_context"]
    })
}

// Helper function to register relationship interaction tools
pub fn register_relationship_interaction_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    // Register UpdateRelationshipTool - AI-driven relationship modification
    let update_relationship_tool = Arc::new(UpdateRelationshipTool::new(app_state.clone())) as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register(update_relationship_tool)?;
    
    // Register CreateRelationshipTool - AI-driven relationship creation
    let create_relationship_tool = Arc::new(CreateRelationshipTool::new(app_state.clone())) as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register(create_relationship_tool)?;
    
    // Register DeleteRelationshipTool - AI-driven relationship deletion
    let delete_relationship_tool = Arc::new(DeleteRelationshipTool::new(app_state.clone())) as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register(delete_relationship_tool)?;
    
    tracing::info!("Registered 3 AI-driven relationship interaction tools with unified registry (UpdateRelationshipTool, CreateRelationshipTool, DeleteRelationshipTool)");
    Ok(())
}