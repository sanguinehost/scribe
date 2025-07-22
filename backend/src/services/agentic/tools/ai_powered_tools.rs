// AI-Powered Foundational Tools for Hierarchical World Model
//
// These tools use Flash/Flash-Lite to provide intelligent, context-aware operations
// that move beyond simple ECS wrappers to sophisticated AI-driven analysis.

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, debug, instrument, warn};
use genai::chat::{SafetySetting, HarmCategory, HarmBlockThreshold};

use crate::{
    models::ecs::{SpatialScale, SalienceTier},
    services::agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    state::AppState,
};

use super::hierarchy_tools::GetEntityHierarchyTool;
use super::structured_output::{
    get_salience_analysis_schema_gemini,
    get_hierarchy_interpretation_schema_gemini,
    get_promotion_analysis_schema_gemini,
};

/// AI-powered tool that interprets natural language requests about entity hierarchies
/// and translates them into formal queries
#[derive(Clone)]
pub struct AnalyzeHierarchyRequestTool {
    app_state: Arc<AppState>,
    get_hierarchy_tool: GetEntityHierarchyTool,
}

impl AnalyzeHierarchyRequestTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        let get_hierarchy_tool = GetEntityHierarchyTool::new(app_state.ecs_entity_manager.clone());
        Self { 
            app_state,
            get_hierarchy_tool,
        }
    }

    /// Build prompt for interpreting natural language hierarchy requests
    fn build_hierarchy_analysis_prompt(&self, request: &str, available_entities: &str) -> String {
        format!(
            r#"You are an intelligent hierarchy analyzer for a dynamic world model system.

Your task is to interpret natural language requests about entity hierarchies and translate them into structured queries.

NATURAL LANGUAGE REQUEST:
"{}"

AVAILABLE ENTITIES:
{}

Your analysis should identify:
1. What specific hierarchy information the user wants
2. Which entities are involved
3. The scope and scale of the query (Cosmic, Planetary, Intimate)
4. Whether this is about containment, command structure, spatial relationships, etc.

RESPONSE FORMAT (JSON):
{{
    "interpretation": "Clear restatement of what the user is asking for",
    "query_type": "hierarchy_path|containment_query|command_structure|spatial_relationships",
    "target_entities": ["entity_name_1", "entity_name_2"],
    "scope": "Cosmic|Planetary|Intimate",
    "reasoning": "Explanation of your interpretation",
    "suggested_query": {{
        "action": "get_entity_hierarchy|custom_query",
        "parameters": {{}}
    }}
}}

Examples:
- "Show me the chain of command for this fleet" → command_structure query
- "What galaxy is this planet in?" → hierarchy_path query  
- "What's contained within this building?" → containment_query
- "How are these star systems related?" → spatial_relationships query

Be precise and actionable in your analysis."#,
            request,
            available_entities
        )
    }

    /// Execute the AI-interpreted hierarchy query
    async fn execute_interpreted_query(&self, interpretation: &HierarchyInterpretation, user_id: Uuid) -> Result<JsonValue, ToolError> {
        match interpretation.suggested_query.action.as_str() {
            "get_entity_hierarchy" => {
                // Use the existing GetEntityHierarchyTool
                if let Some(entity_name) = interpretation.target_entities.first() {
                    // For now, we'll need the entity ID. In a real implementation,
                    // we'd have an entity name-to-ID resolution service
                    warn!("Entity name to ID resolution not implemented. Using placeholder for: {}", entity_name);
                    
                    // Return interpretation results for now
                    Ok(json!({
                        "interpretation": interpretation,
                        "status": "interpreted_but_not_executed",
                        "reason": "Entity name to ID resolution needed"
                    }))
                } else {
                    Err(ToolError::InvalidParams("No target entities identified".to_string()))
                }
            }
            "custom_query" => {
                // Handle custom hierarchy queries
                Ok(json!({
                    "interpretation": interpretation,
                    "status": "custom_query_interpreted",
                    "reasoning": interpretation.reasoning
                }))
            }
            _ => {
                Err(ToolError::InvalidParams(format!("Unknown query action: {}", interpretation.suggested_query.action)))
            }
        }
    }
}

/// Structured interpretation of hierarchy requests
#[derive(Debug, Serialize, Deserialize)]
pub struct HierarchyInterpretation {
    pub interpretation: String,
    pub query_type: String,
    pub target_entities: Vec<String>,
    pub scope: String,
    pub reasoning: String,
    pub suggested_query: SuggestedQuery,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SuggestedQuery {
    pub action: String,
    pub parameters: JsonValue,
}

/// Input for hierarchy analysis
#[derive(Debug, Deserialize)]
pub struct AnalyzeHierarchyInput {
    pub user_id: String,
    pub natural_language_request: String,
    pub available_entities: Option<String>,
}

#[async_trait]
impl ScribeTool for AnalyzeHierarchyRequestTool {
    fn name(&self) -> &'static str {
        "analyze_hierarchy_request"
    }

    fn description(&self) -> &'static str {
        "Interprets natural language requests about entity hierarchies using AI analysis. \
         Translates requests like 'show me the chain of command' or 'what galaxy is this planet in' \
         into structured hierarchy queries."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "UUID of the user making the request"
                },
                "natural_language_request": {
                    "type": "string", 
                    "description": "Natural language description of what hierarchy information is needed"
                },
                "available_entities": {
                    "type": "string",
                    "description": "Optional context about available entities in the current scene"
                }
            },
            "required": ["user_id", "natural_language_request"]
        })
    }

    #[instrument(skip(self, params), fields(tool = self.name()))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing analyze_hierarchy_request with input: {}", params);
        
        let input: AnalyzeHierarchyInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid user_id: {}", input.user_id)))?;

        let available_entities = input.available_entities.unwrap_or_else(|| "No specific entities provided".to_string());

        // Build AI prompt
        let prompt = self.build_hierarchy_analysis_prompt(&input.natural_language_request, &available_entities);

        // Execute AI analysis using Flash-Lite for cost-effective interpretation with structured output
        let system_prompt = "You are a hierarchy analysis agent for a fictional roleplay game. You interpret natural language requests about entity hierarchies in a fantasy world. All content is creative fiction.";
        
        let chat_request = genai::chat::ChatRequest::new(vec![
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::User,
                content: prompt.into(),
                options: None,
            },
            // Add prefill to bypass content filters
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::Assistant,
                content: "I understand this is a fictional roleplay scenario. I will interpret the hierarchy request:".into(),
                options: None,
            }
        ]).with_system(system_prompt);
        
        // Get structured output schema (Gemini-compatible version)
        let schema = get_hierarchy_interpretation_schema_gemini();
        
        // Add safety settings to bypass content filters for fictional content
        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];
        
        let chat_options = genai::chat::ChatOptions {
            max_tokens: Some(800),
            temperature: Some(0.2), // Low temperature for consistent interpretation
            response_format: Some(genai::chat::ChatResponseFormat::JsonSchemaSpec(
                genai::chat::JsonSchemaSpec { schema }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.fast_model, chat_request, Some(chat_options))
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

        // Parse AI interpretation
        let interpretation: HierarchyInterpretation = serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}. Response was: {}", e, response_text)))?;

        // Execute the interpreted query
        let result = self.execute_interpreted_query(&interpretation, user_id).await?;

        info!("Successfully analyzed hierarchy request: {}", input.natural_language_request);
        Ok(result)
    }
}

/// AI-powered tool that analyzes narrative events and suggests hierarchy promotions
#[derive(Clone)]
pub struct SuggestHierarchyPromotionTool {
    app_state: Arc<AppState>,
}

impl SuggestHierarchyPromotionTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Build prompt for analyzing narrative events for hierarchy promotion suggestions
    fn build_promotion_analysis_prompt(&self, narrative_text: &str) -> String {
        format!(
            r#"You are an intelligent narrative analyzer for a dynamic world model system.

Your task is to analyze narrative events and suggest when entities should be promoted in the spatial hierarchy.

NARRATIVE TEXT:
"{}"

Analyze this text for entities that have gained narrative importance and might warrant hierarchy promotion:

1. **Entities mentioned frequently** - repeated references suggest importance
2. **Entities with expanded roles** - background entities becoming central
3. **New scope revelations** - mentions of larger organizational structures
4. **Command/authority relationships** - mentions of fleets, organizations, chains of command

RESPONSE FORMAT (JSON):
{{
    "analysis": "Summary of narrative patterns observed",
    "promotion_suggestions": [
        {{
            "entity_name": "Name of entity to promote",
            "current_perceived_tier": "Core|Secondary|Flavor",
            "suggested_new_tier": "Core|Secondary", 
            "reasoning": "Why this promotion makes sense",
            "evidence": ["Quote 1", "Quote 2"],
            "suggested_hierarchy": {{
                "new_parent_name": "Suggested parent entity name",
                "scale": "Cosmic|Planetary|Intimate",
                "relationship_type": "command_structure|spatial_containment|organizational"
            }}
        }}
    ],
    "confidence": 0.85
}}

Examples of promotion triggers:
- "The Crimson Fleet has been mentioned 5 times" → Fleet should be Core entity
- "Captain Sarah is commanding multiple ships" → Promote to command structure
- "This tavern is where all the action happens" → Promote from Flavor to Secondary

Focus on actionable promotions that reflect the narrative's actual importance patterns."#,
            narrative_text
        )
    }
}

/// Input for hierarchy promotion suggestions
#[derive(Debug, Deserialize)]
pub struct SuggestPromotionInput {
    pub user_id: String,
    pub narrative_text: String,
    pub current_entities: Option<Vec<String>>,
}

/// Suggestion for promoting an entity's hierarchy
#[derive(Debug, Serialize, Deserialize)]
pub struct PromotionSuggestion {
    pub entity_name: String,
    pub current_perceived_tier: String,
    pub suggested_new_tier: String,
    pub reasoning: String,
    pub evidence: Vec<String>,
    pub suggested_hierarchy: SuggestedHierarchy,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SuggestedHierarchy {
    pub new_parent_name: String,
    pub scale: String,
    pub relationship_type: String,
}

/// Output from promotion analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct PromotionAnalysis {
    pub analysis: String,
    pub promotion_suggestions: Vec<PromotionSuggestion>,
    pub confidence: f64,
}

#[async_trait]
impl ScribeTool for SuggestHierarchyPromotionTool {
    fn name(&self) -> &'static str {
        "suggest_hierarchy_promotion"
    }

    fn description(&self) -> &'static str {
        "Analyzes narrative events using AI to suggest when entities should be promoted \
         in the hierarchy. Detects when background entities become narratively important \
         and suggests appropriate hierarchy promotions."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "UUID of the user"
                },
                "narrative_text": {
                    "type": "string",
                    "description": "Recent narrative text to analyze for promotion opportunities"
                },
                "current_entities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of currently known entities for context"
                }
            },
            "required": ["user_id", "narrative_text"]
        })
    }

    #[instrument(skip(self, params), fields(tool = self.name()))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing suggest_hierarchy_promotion with input: {}", params);
        
        let input: SuggestPromotionInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;

        let _user_id = Uuid::parse_str(&input.user_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid user_id: {}", input.user_id)))?;

        // Build AI prompt
        let prompt = self.build_promotion_analysis_prompt(&input.narrative_text);

        // Execute AI analysis using Flash for sophisticated narrative analysis with structured output
        let system_prompt = "You are a narrative analysis agent for a fictional roleplay game. You analyze story events to suggest when entities should be promoted in the spatial hierarchy. All content is creative fiction.";
        
        let chat_request = genai::chat::ChatRequest::new(vec![
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::User,
                content: prompt.into(),
                options: None,
            },
            // Add prefill to bypass content filters
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::Assistant,
                content: "I understand this is a fictional roleplay scenario. I will analyze the narrative for hierarchy promotion opportunities:".into(),
                options: None,
            }
        ]).with_system(system_prompt);
        
        // Get structured output schema (Gemini-compatible version)
        let schema = get_promotion_analysis_schema_gemini();
        
        // Add safety settings to bypass content filters for fictional content
        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];
        
        let chat_options = genai::chat::ChatOptions {
            max_tokens: Some(1200),
            temperature: Some(0.3), // Moderate temperature for creative but focused analysis
            response_format: Some(genai::chat::ChatResponseFormat::JsonSchemaSpec(
                genai::chat::JsonSchemaSpec { schema }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.fast_model, chat_request, Some(chat_options))
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

        // Parse AI analysis
        let analysis: PromotionAnalysis = serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}. Response was: {}", e, response_text)))?;

        info!("AI suggested {} hierarchy promotions from narrative analysis", analysis.promotion_suggestions.len());
        
        Ok(serde_json::to_value(analysis)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to serialize result: {}", e)))?)
    }
}

/// AI-powered tool for automatic salience tier assignment and updates
#[derive(Clone)]
pub struct UpdateSalienceTool {
    app_state: Arc<AppState>,
}

impl UpdateSalienceTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Build prompt for AI-driven salience analysis
    fn build_salience_analysis_prompt(&self, narrative_context: &str, entity_name: &str, current_tier: Option<&str>) -> String {
        let current_info = match current_tier {
            Some(tier) => format!("Current salience tier: {}", tier),
            None => "Entity not yet assigned a salience tier".to_string(),
        };

        format!(
            r#"You are an intelligent salience analyzer for a dynamic world model system.

Your task is to analyze narrative context and determine the appropriate salience tier for an entity.

SALIENCE TIERS:
- **Core**: Player Characters, major NPCs, key locations (always tracked, persistent)
- **Secondary**: Supporting characters, important items, notable locations (tracked when relevant)  
- **Flavor**: Scenery, background details, atmospheric elements (generated on-demand, garbage collected)

ENTITY: "{}"
{}

NARRATIVE CONTEXT:
"{}"

Analyze the entity's role and importance in this narrative context:

1. **Narrative Importance**: How central is this entity to the story?
2. **Interaction Frequency**: How often do characters interact with this entity?
3. **Plot Relevance**: Does this entity drive or significantly influence events?
4. **Persistence Need**: Should this entity persist across scenes/sessions?
5. **Scale Appropriateness**: What scale is this entity operating at?

RESPONSE FORMAT (JSON):
{{
    "analysis": "Detailed analysis of the entity's narrative role",
    "recommended_tier": "Core|Secondary|Flavor",
    "reasoning": "Explanation for the recommended tier",
    "confidence": 0.85,
    "scale_context": "Cosmic|Planetary|Intimate",
    "interaction_indicators": ["evidence1", "evidence2"],
    "persistence_reasoning": "Why this entity should/shouldn't persist",
    "change_from_current": "upgrade|downgrade|maintain|initial_assignment"
}}

Examples:
- Main character → Core (always central to narrative)
- Important bartender who gives quests → Secondary (relevant when in tavern)
- Random background NPC mentioned once → Flavor (atmospheric only)
- Death Star → Core (major plot element)
- Imperial Fleet → Secondary (important but not always central)
- Background starships → Flavor (scenery)"#,
            entity_name,
            current_info,
            narrative_context
        )
    }

    /// Apply the AI-determined salience update
    async fn apply_salience_update(&self, user_id: Uuid, entity_name: &str, analysis: &SalienceAnalysis) -> Result<JsonValue, ToolError> {
        let salience_tier = match analysis.recommended_tier.as_str() {
            "Core" => SalienceTier::Core,
            "Secondary" => SalienceTier::Secondary,
            "Flavor" => SalienceTier::Flavor,
            _ => return Err(ToolError::ExecutionFailed(format!("Invalid salience tier: {}", analysis.recommended_tier))),
        };

        let scale_context = match analysis.scale_context.as_str() {
            "Cosmic" => Some(SpatialScale::Cosmic),
            "Planetary" => Some(SpatialScale::Planetary), 
            "Intimate" => Some(SpatialScale::Intimate),
            _ => None,
        };

        // Step 1: Use FindEntityTool to resolve entity name to ID
        let find_entity_tool = super::world_interaction_tools::FindEntityTool::new(
            self.app_state.ecs_entity_manager.clone()
        );
        
        let find_params = json!({
            "user_id": user_id.to_string(),
            "criteria": {
                "type": "ByName",
                "name": entity_name
            },
            "limit": 1
        });
        
        let find_result = find_entity_tool.execute(&find_params).await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to find entity: {}", e)))?;
            
        let entities = find_result.get("entities").and_then(|e| e.as_array())
            .ok_or_else(|| ToolError::ExecutionFailed("Invalid find_entity response".to_string()))?;
            
        if entities.is_empty() {
            return Ok(json!({
                "entity_name": entity_name,
                "analysis": analysis,
                "status": "entity_not_found",
                "reason": format!("Entity '{}' not found in ECS. Entity must exist before salience can be updated.", entity_name),
                "recommendation": "Create the entity first using create_entity tool"
            }));
        }
        
        let entity = &entities[0];
        let entity_id_str = entity.get("entity_id").and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::ExecutionFailed("Missing entity_id in response".to_string()))?;
        let entity_id = Uuid::parse_str(entity_id_str)
            .map_err(|_| ToolError::ExecutionFailed(format!("Invalid entity_id: {}", entity_id_str)))?;
        
        // Get current salience tier for comparison
        let mut current_tier_str = "Unknown";
        if let Some(components) = entity.get("components").and_then(|v| v.as_array()) {
            for component in components {
                if component.get("type").and_then(|v| v.as_str()) == Some("Salience") {
                    if let Some(data) = component.get("data") {
                        if let Some(tier) = data.get("tier").and_then(|t| t.as_str()) {
                            current_tier_str = tier;
                        }
                    }
                }
            }
        }
        
        // Step 2: Update the entity's salience using entity_manager
        let update_reason = format!(
            "AI Analysis: {} (confidence: {:.2}). {}",
            analysis.reasoning,
            analysis.confidence,
            analysis.persistence_reasoning
        );
        
        let entity_manager = &self.app_state.ecs_entity_manager;
        entity_manager.update_entity_salience(
            user_id,
            entity_id,
            salience_tier,
            update_reason.clone(),
        ).await.map_err(|e| ToolError::AppError(e))?;
        
        // Step 3: Return the actual update result
        Ok(json!({
            "entity_name": entity_name,
            "entity_id": entity_id.to_string(),
            "previous_tier": current_tier_str,
            "new_tier": analysis.recommended_tier,
            "analysis": analysis,
            "status": "applied",
            "update_reason": update_reason,
            "scale_context": scale_context.map(|s| format!("{:?}", s)),
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }
}

/// Input for salience analysis and update
#[derive(Debug, Deserialize)]
pub struct UpdateSalienceInput {
    pub user_id: String,
    pub entity_name: String,
    pub narrative_context: String,
    pub current_tier: Option<String>,
}

/// AI analysis result for salience assignment
#[derive(Debug, Serialize, Deserialize)]
pub struct SalienceAnalysis {
    pub analysis: String,
    pub recommended_tier: String,
    pub reasoning: String,
    pub confidence: f64,
    pub scale_context: String,
    pub interaction_indicators: Vec<String>,
    pub persistence_reasoning: String,
    pub change_from_current: String,
}

#[async_trait]
impl ScribeTool for UpdateSalienceTool {
    fn name(&self) -> &'static str {
        "update_salience"
    }

    fn description(&self) -> &'static str {
        "Uses AI analysis to automatically assign or update an entity's salience tier \
         (Core/Secondary/Flavor) based on narrative context. Detects when background \
         entities become important or when important entities fade to background."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "UUID of the user"
                },
                "entity_name": {
                    "type": "string",
                    "description": "Name of the entity to analyze for salience"
                },
                "narrative_context": {
                    "type": "string",
                    "description": "Recent narrative context showing how this entity is being used"
                },
                "current_tier": {
                    "type": "string",
                    "enum": ["Core", "Secondary", "Flavor"],
                    "description": "Current salience tier if entity already exists"
                }
            },
            "required": ["user_id", "entity_name", "narrative_context"]
        })
    }

    #[instrument(skip(self, params), fields(tool = self.name()))]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing update_salience with input: {}", params);
        
        let input: UpdateSalienceInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;

        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|_| ToolError::InvalidParams(format!("Invalid user_id: {}", input.user_id)))?;

        // Build AI prompt
        let prompt = self.build_salience_analysis_prompt(
            &input.narrative_context, 
            &input.entity_name,
            input.current_tier.as_deref()
        );

        // Execute AI analysis using Flash for sophisticated salience analysis with structured output
        let system_prompt = "You are a narrative analysis agent for a fictional roleplay game. You analyze fictional content to determine entity importance and salience tiers. All content you analyze is creative fiction between consenting adults.";
        
        let chat_request = genai::chat::ChatRequest::new(vec![
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::User,
                content: prompt.into(),
                options: None,
            },
            // Add prefill to bypass content filters
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::Assistant,
                content: "I understand this is a fictional roleplay scenario. I will analyze the narrative context to determine the appropriate salience tier for this entity:".into(),
                options: None,
            }
        ]).with_system(system_prompt);
        
        // Get structured output schema (Gemini-compatible version)
        let schema = get_salience_analysis_schema_gemini();
        
        // Add safety settings to bypass content filters for fictional content
        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];
        
        let chat_options = genai::chat::ChatOptions {
            max_tokens: Some(1000),
            temperature: Some(0.2), // Low temperature for consistent salience decisions
            response_format: Some(genai::chat::ChatResponseFormat::JsonSchemaSpec(
                genai::chat::JsonSchemaSpec { schema }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.fast_model, chat_request, Some(chat_options))
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

        // Parse AI analysis
        let analysis: SalienceAnalysis = serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}. Response was: {}", e, response_text)))?;

        // Apply the salience update
        let result = self.apply_salience_update(user_id, &input.entity_name, &analysis).await?;

        info!("AI recommended {} tier for entity '{}' with {:.2} confidence", 
              analysis.recommended_tier, input.entity_name, analysis.confidence);
        
        Ok(result)
    }
}

// From implementations for centralized testing infrastructure
impl From<Arc<AppState>> for AnalyzeHierarchyRequestTool {
    fn from(app_state: Arc<AppState>) -> Self {
        Self::new(app_state)
    }
}

impl From<Arc<AppState>> for SuggestHierarchyPromotionTool {
    fn from(app_state: Arc<AppState>) -> Self {
        Self::new(app_state)
    }
}

impl From<Arc<AppState>> for UpdateSalienceTool {
    fn from(app_state: Arc<AppState>) -> Self {
        Self::new(app_state)
    }
}