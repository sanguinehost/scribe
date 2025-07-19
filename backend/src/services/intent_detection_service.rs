use std::sync::Arc;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value as JsonValue};
use chrono::{DateTime, Utc, Duration};
use tracing::{info, instrument};

use crate::{
    llm::AiClient,
    errors::AppError,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryIntent {
    pub intent_type: IntentType,
    pub focus_entities: Vec<EntityFocus>,
    pub time_scope: TimeScope,
    pub spatial_scope: Option<SpatialScope>,
    pub reasoning_depth: ReasoningDepth,
    pub context_priorities: Vec<ContextPriority>,
    pub confidence: f32,
}

/// Enhanced narrative intent structure for AI-driven analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeIntent {
    /// AI-driven analysis of the narrative situation and user's intent
    pub narrative_analysis: String,
    /// Context requirements determined by AI analysis
    pub context_needs: Vec<String>,
    /// Scene context information from AI interpretation
    pub scene_context: HashMap<String, serde_json::Value>,
    /// Entities the AI identified as important for this narrative moment
    pub focus_entities: Vec<EntityFocus>,
    /// Time scope relevant to this narrative intent
    pub time_scope: TimeScope,
    /// Spatial scope if location is important to the narrative
    pub spatial_scope: Option<SpatialScope>,
    /// How deep the reasoning should go for this narrative context
    pub reasoning_depth: ReasoningDepth,
    /// Priority order of context types for this narrative situation
    pub context_priorities: Vec<ContextPriority>,
    /// AI-suggested query strategies for gathering context
    pub query_strategies: Vec<String>,
    /// AI's confidence in this narrative analysis
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntentType {
    CausalAnalysis,      // "What caused X?"
    RelationshipQuery,   // "Who trusts Y?"
    StateInquiry,        // "Where is Z?"
    TemporalAnalysis,    // "What happened between T1 and T2?"
    SpatialAnalysis,     // "What's in location L?"
    PredictiveQuery,     // "What might happen if...?"
    NarrativeGeneration, // "Continue the story"
    ComparisonQuery,     // "How do X and Y differ?"
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntityFocus {
    pub name: String,
    pub entity_type: Option<String>,
    pub priority: f32, // 0.0-1.0
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TimeScope {
    Current,
    Recent(Duration),
    Historical(DateTime<Utc>),
    Range(DateTime<Utc>, DateTime<Utc>),
    AllTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpatialScope {
    pub location_name: Option<String>,
    pub radius: Option<f64>,
    pub include_contained: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReasoningDepth {
    Surface,    // Just facts
    Analytical, // Include relationships
    Causal,     // Include causality
    Deep,       // Full reasoning chains
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContextPriority {
    Entities,
    Relationships,
    RecentEvents,
    SpatialContext,
    CausalChains,
    TemporalState,
    SecurityContext,
    ExternalData,
}

pub struct IntentDetectionService {
    ai_client: Arc<dyn AiClient>,
    model: String,
}

impl IntentDetectionService {
    pub fn new(ai_client: Arc<dyn AiClient>, model: String) -> Self {
        Self { ai_client, model }
    }

    #[instrument(skip(self), fields(query_len = user_query.len()))]
    pub async fn detect_intent(
        &self,
        user_query: &str,
        conversation_context: Option<&str>,
    ) -> Result<QueryIntent, AppError> {
        info!("Using Flash-Lite for AI-driven intent detection for query: {}", user_query);
        
        // Use Flash-Lite for cost-effective intent analysis
        let prompt = self.build_flash_intent_detection_prompt(user_query, conversation_context);
        
        // Add system prompt and prefill to prevent content filtering
        let system_prompt = "You are an advanced intent detection AI for a fictional roleplay game's narrative intelligence system. Your task is to analyze user queries and detect their narrative intent for creative storytelling purposes.";
        
        let chat_request = genai::chat::ChatRequest::new(vec![
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::User,
                content: prompt.into(),
                options: None,
            },
            // Add prefill to bypass content filters
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::Assistant,
                content: "I understand this is for a fictional roleplay game. I'll analyze the user's query and detect their narrative intent to help with creative storytelling.".into(),
                options: None,
            }
        ]).with_system(system_prompt);
        
        // Get structured output schema
        let schema = get_intent_detection_schema();
        
        // Set up safety settings to prevent content filtering
        let safety_settings = vec![
            genai::chat::SafetySetting::new(
                genai::chat::HarmCategory::Harassment,
                genai::chat::HarmBlockThreshold::BlockNone,
            ),
            genai::chat::SafetySetting::new(
                genai::chat::HarmCategory::HateSpeech,
                genai::chat::HarmBlockThreshold::BlockNone,
            ),
            genai::chat::SafetySetting::new(
                genai::chat::HarmCategory::SexuallyExplicit,
                genai::chat::HarmBlockThreshold::BlockNone,
            ),
            genai::chat::SafetySetting::new(
                genai::chat::HarmCategory::DangerousContent,
                genai::chat::HarmBlockThreshold::BlockNone,
            ),
            genai::chat::SafetySetting::new(
                genai::chat::HarmCategory::CivicIntegrity,
                genai::chat::HarmBlockThreshold::BlockNone,
            ),
        ];
        
        let mut chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1200)
            .with_temperature(0.1) // Low temperature for consistent analysis
            .with_safety_settings(safety_settings);
            
        // Enable structured output using JSON schema
        chat_options = chat_options.with_response_format(genai::chat::ChatResponseFormat::JsonSchemaSpec(
            genai::chat::JsonSchemaSpec { schema }
        ));
        
        let response = self.ai_client.exec_chat(
            &self.model, // Use configured model for structured analysis
            chat_request,
            Some(chat_options),
        ).await?;

        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        self.parse_flash_intent_response(&response_text)
    }

    /// AI-driven narrative intent detection using Flash-Lite
    #[instrument(skip(self), fields(query_len = user_query.len()))]
    pub async fn detect_narrative_intent(
        &self,
        user_query: &str,
        conversation_context: Option<&str>,
    ) -> Result<NarrativeIntent, AppError> {
        info!("Using Flash for AI-driven narrative intent analysis for query: {}", user_query);
        
        // Use Flash for more sophisticated narrative analysis
        let prompt = self.build_flash_narrative_intent_prompt(user_query, conversation_context);
        
        // Add system prompt and prefill to prevent content filtering
        let system_prompt = "You are an advanced intent detection AI for a fictional roleplay game's narrative intelligence system. Your task is to analyze user queries and detect their narrative intent for creative storytelling purposes.";
        
        let chat_request = genai::chat::ChatRequest::new(vec![
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::User,
                content: prompt.into(),
                options: None,
            },
            // Add prefill to bypass content filters
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::Assistant,
                content: "I understand this is for a fictional roleplay game. I'll analyze the user's query and detect their narrative intent to help with creative storytelling.".into(),
                options: None,
            }
        ]).with_system(system_prompt);
        
        // Get structured output schema
        let schema = get_narrative_intent_schema();
        
        // Set up safety settings to prevent content filtering
        let safety_settings = vec![
            genai::chat::SafetySetting::new(
                genai::chat::HarmCategory::Harassment,
                genai::chat::HarmBlockThreshold::BlockNone,
            ),
            genai::chat::SafetySetting::new(
                genai::chat::HarmCategory::HateSpeech,
                genai::chat::HarmBlockThreshold::BlockNone,
            ),
            genai::chat::SafetySetting::new(
                genai::chat::HarmCategory::SexuallyExplicit,
                genai::chat::HarmBlockThreshold::BlockNone,
            ),
            genai::chat::SafetySetting::new(
                genai::chat::HarmCategory::DangerousContent,
                genai::chat::HarmBlockThreshold::BlockNone,
            ),
            genai::chat::SafetySetting::new(
                genai::chat::HarmCategory::CivicIntegrity,
                genai::chat::HarmBlockThreshold::BlockNone,
            ),
        ];
        
        let mut chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1800) // More tokens for comprehensive narrative analysis
            .with_temperature(0.2) // Slightly higher for creative narrative understanding
            .with_safety_settings(safety_settings);
            
        // Enable structured output using JSON schema
        chat_options = chat_options.with_response_format(genai::chat::ChatResponseFormat::JsonSchemaSpec(
            genai::chat::JsonSchemaSpec { schema }
        ));
        
        let response = self.ai_client.exec_chat(
            &self.model, // Use configured model for advanced narrative reasoning
            chat_request,
            Some(chat_options),
        ).await?;

        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        self.parse_flash_narrative_intent_response(&response_text)
    }

    /// Build AI-driven prompt for intent detection using Flash-Lite
    fn build_flash_intent_detection_prompt(&self, query: &str, context: Option<&str>) -> String {
        let context_section = context.map_or(String::new(), |c| format!("Recent Conversation:\n{}\n\n", c));
        
        format!(r#"You are an expert AI analyst for an intelligent narrative system. Your task is to analyze user queries and determine their underlying intent, focus, and context requirements using advanced reasoning.

{}User Query: "{}"

ANALYSIS TASK:
Perform deep analysis of this query to understand what the user really wants to achieve. Don't just categorize - think about the narrative intent, emotional context, and practical needs.

Provide your analysis including:
- The intent type from: CausalAnalysis, RelationshipQuery, StateInquiry, TemporalAnalysis, SpatialAnalysis, PredictiveQuery, NarrativeGeneration, ComparisonQuery
- Key entities mentioned or implied in the query with their priority
- Time scope relevant to the query (Current, Recent, Historical, Range, or AllTime)
- Spatial scope if location is relevant
- Required reasoning depth (Surface, Moderate, or Deep)
- Context priorities in order of importance
- Your confidence level in this analysis

REASONING GUIDELINES:
- CausalAnalysis: "What caused X?" "Why did Y happen?" - needs Deep reasoning
- RelationshipQuery: "How do X and Y relate?" - needs Analytical reasoning  
- StateInquiry: "Where is X?" "What's X's status?" - needs Surface to Analytical
- TemporalAnalysis: "What happened when?" - needs timeline context
- SpatialAnalysis: "What's at location Y?" - needs spatial context
- PredictiveQuery: "What might happen if?" - needs Causal reasoning
- NarrativeGeneration: Story continuation - needs comprehensive context
- ComparisonQuery: "How do X and Y differ?" - needs comparative analysis

PRIORITY SELECTION:
- Entities: Direct character/object focus
- Relationships: Social/causal connections  
- RecentEvents: Immediate history relevance
- SpatialContext: Location-based needs
- CausalChains: Cause-effect relationships
- TemporalState: Time-based context

Be intelligent and context-aware. Consider what the user REALLY needs to get a satisfying answer."#, context_section, query)
    }

    /// Build AI-driven prompt for narrative intent analysis using Flash
    fn build_flash_narrative_intent_prompt(&self, query: &str, context: Option<&str>) -> String {
        let context_section = context.map_or(String::new(), |c| format!("Recent Conversation Context:\n{}\n\n", c));
        
        format!(r#"You are an expert narrative AI analyst specializing in interactive storytelling. Your role is to deeply understand narrative intent behind user actions and determine optimal context for rich, engaging responses.

{}User's Narrative Action: "{}"

DEEP NARRATIVE ANALYSIS:
Analyze this action for its narrative significance. Think about story structure, character development, emotional beats, pacing, and world-building implications. What does the user want to accomplish narratively?

Provide your comprehensive analysis including:
- A detailed narrative analysis of the user's intent and story goals
- Specific context needs for this narrative moment
- Scene context including scene type, narrative goal, emotional tone, and relationship focus
- Focus entities with their narrative roles and priorities
- Time scope relevant to the narrative moment
- Spatial scope and how location affects the narrative
- Required reasoning depth for this narrative context
- Context priorities in order of importance
- Specific query strategies for gathering the needed context
- Your confidence level in this narrative analysis

NARRATIVE SCENE TYPES:
- "combat_encounter", "character_dialogue", "exploration_discovery"
- "family_domestic", "political_intrigue", "emotional_revelation" 
- "world_building", "character_development", "plot_advancement"

CONTEXT NEEDS EXAMPLES:
- "Character's emotional state and recent trauma"
- "Location atmospheric details and environmental threats"
- "Historical significance of current setting"
- "Relationship dynamics between involved parties"
- "Character abilities relevant to current challenge"

QUERY STRATEGIES:
- "get_entity_emotional_state", "find_recent_relationship_interactions"
- "retrieve_location_atmospheric_details", "analyze_combat_readiness"
- "check_character_skills_equipment", "get_historical_significance"

Think like a master storyteller analyzing what context would make this moment most dramatically satisfying and narratively rich."#, context_section, query)
    }

    /// Parse AI response from Flash intent detection
    fn parse_flash_intent_response(&self, response: &str) -> Result<QueryIntent, AppError> {
        let cleaned = response.trim();
        
        let json_value: serde_json::Value = serde_json::from_str(cleaned)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse Flash intent response: {}", e)))?;
        
        // Parse intent type with AI reasoning
        let intent_type = match json_value["intent_type"].as_str() {
            Some("CausalAnalysis") => IntentType::CausalAnalysis,
            Some("RelationshipQuery") => IntentType::RelationshipQuery,
            Some("StateInquiry") => IntentType::StateInquiry,
            Some("TemporalAnalysis") => IntentType::TemporalAnalysis,
            Some("SpatialAnalysis") => IntentType::SpatialAnalysis,
            Some("PredictiveQuery") => IntentType::PredictiveQuery,
            Some("NarrativeGeneration") => IntentType::NarrativeGeneration,
            Some("ComparisonQuery") => IntentType::ComparisonQuery,
            _ => return Err(AppError::SerializationError("AI provided invalid intent_type".to_string())),
        };

        // Parse AI-identified focus entities
        let focus_entities = json_value["focus_entities"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|entity_value| {
                Some(EntityFocus {
                    name: entity_value.get("name")?.as_str()?.to_string(),
                    entity_type: entity_value.get("entity_type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    priority: entity_value.get("priority")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.5) as f32,
                    required: entity_value.get("required")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                })
            })
            .collect();

        // Parse AI-determined time scope
        let time_scope = self.parse_ai_time_scope(&json_value["time_scope"])?;
        
        // Parse AI-identified spatial scope
        let spatial_scope = if let Some(spatial_value) = json_value.get("spatial_scope") {
            if spatial_value.is_null() {
                None
            } else {
                Some(SpatialScope {
                    location_name: spatial_value.get("location_name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    radius: spatial_value.get("radius")
                        .and_then(|v| v.as_f64()),
                    include_contained: spatial_value.get("include_contained")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                })
            }
        } else {
            None
        };

        // Parse AI-determined reasoning depth
        let reasoning_depth = match json_value["reasoning_depth"].as_str() {
            Some("Surface") => ReasoningDepth::Surface,
            Some("Analytical") => ReasoningDepth::Analytical,
            Some("Causal") => ReasoningDepth::Causal,
            Some("Deep") => ReasoningDepth::Deep,
            _ => ReasoningDepth::Analytical, // AI fallback
        };

        // Parse AI-prioritized context priorities
        let context_priorities = json_value["context_priorities"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|priority_value| {
                match priority_value.as_str() {
                    Some("Entities") => Some(ContextPriority::Entities),
                    Some("Relationships") => Some(ContextPriority::Relationships),
                    Some("RecentEvents") => Some(ContextPriority::RecentEvents),
                    Some("SpatialContext") => Some(ContextPriority::SpatialContext),
                    Some("CausalChains") => Some(ContextPriority::CausalChains),
                    Some("TemporalState") => Some(ContextPriority::TemporalState),
                    Some("SecurityContext") => Some(ContextPriority::SecurityContext),
                    Some("ExternalData") => Some(ContextPriority::ExternalData),
                    _ => None,
                }
            })
            .collect();

        Ok(QueryIntent {
            intent_type,
            focus_entities,
            time_scope,
            spatial_scope,
            reasoning_depth,
            context_priorities,
            confidence: json_value["confidence"]
                .as_f64()
                .unwrap_or(0.5)
                .clamp(0.0, 1.0) as f32,
        })
    }

    /// Parse AI response from Flash narrative intent analysis
    fn parse_flash_narrative_intent_response(&self, response: &str) -> Result<NarrativeIntent, AppError> {
        let cleaned = response.trim();
        
        let json_value: serde_json::Value = serde_json::from_str(cleaned)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse Flash narrative response: {}", e)))?;
        
        // Extract AI narrative analysis
        let narrative_analysis = json_value["narrative_analysis"]
            .as_str()
            .ok_or_else(|| AppError::SerializationError("AI didn't provide narrative_analysis".to_string()))?
            .to_string();
        
        // Extract AI-determined context needs
        let context_needs = json_value["context_needs"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        
        // Extract AI scene context analysis
        let scene_context = json_value["scene_context"]
            .as_object()
            .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_else(HashMap::new);
        
        // Parse AI-identified focus entities with narrative roles
        let focus_entities = json_value["focus_entities"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|entity_value| {
                Some(EntityFocus {
                    name: entity_value.get("name")?.as_str()?.to_string(),
                    entity_type: entity_value.get("context_role")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    priority: entity_value.get("priority")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.5) as f32,
                    required: entity_value.get("required")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                })
            })
            .collect();
        
        // Parse AI narrative time scope
        let time_scope = self.parse_ai_narrative_time_scope(&json_value["time_scope"])?;
        
        // Parse AI spatial scope with narrative context
        let spatial_scope = if let Some(spatial_value) = json_value.get("spatial_scope") {
            if spatial_value.is_null() {
                None
            } else {
                Some(SpatialScope {
                    location_name: spatial_value.get("location_name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    radius: spatial_value.get("radius")
                        .and_then(|v| v.as_f64()),
                    include_contained: spatial_value.get("include_contained")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                })
            }
        } else {
            None
        };
        
        // Parse AI reasoning depth
        let reasoning_depth = match json_value["reasoning_depth"].as_str() {
            Some("Surface") => ReasoningDepth::Surface,
            Some("Analytical") => ReasoningDepth::Analytical,
            Some("Causal") => ReasoningDepth::Causal,
            Some("Deep") => ReasoningDepth::Deep,
            _ => ReasoningDepth::Analytical,
        };
        
        // Parse AI context priorities
        let context_priorities = json_value["context_priorities"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|priority_value| {
                match priority_value.as_str() {
                    Some("Entities") => Some(ContextPriority::Entities),
                    Some("Relationships") => Some(ContextPriority::Relationships),
                    Some("RecentEvents") => Some(ContextPriority::RecentEvents),
                    Some("SpatialContext") => Some(ContextPriority::SpatialContext),
                    Some("CausalChains") => Some(ContextPriority::CausalChains),
                    Some("TemporalState") => Some(ContextPriority::TemporalState),
                    Some("SecurityContext") => Some(ContextPriority::SecurityContext),
                    Some("ExternalData") => Some(ContextPriority::ExternalData),
                    _ => None,
                }
            })
            .collect();
        
        // Parse AI query strategies
        let query_strategies = json_value["query_strategies"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        
        // Parse AI confidence
        let confidence = json_value["confidence"]
            .as_f64()
            .unwrap_or(0.5)
            .clamp(0.0, 1.0) as f32;
        
        Ok(NarrativeIntent {
            narrative_analysis,
            context_needs,
            scene_context,
            focus_entities,
            time_scope,
            spatial_scope,
            reasoning_depth,
            context_priorities,
            query_strategies,
            confidence,
        })
    }

    /// Parse AI-determined time scope
    fn parse_ai_time_scope(&self, time_value: &serde_json::Value) -> Result<TimeScope, AppError> {
        let scope_type = time_value.get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::SerializationError("AI didn't specify time_scope type".to_string()))?;

        match scope_type {
            "Current" => Ok(TimeScope::Current),
            "AllTime" | "All" => Ok(TimeScope::AllTime), // Support both for backward compatibility
            "Recent" => {
                let duration_hours = time_value.get("duration_hours")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(24.0);
                Ok(TimeScope::Recent(Duration::hours(duration_hours as i64)))
            }
            "Historical" => {
                if let Some(start_time_str) = time_value.get("start_time").and_then(|v| v.as_str()) {
                    let start_time = DateTime::parse_from_rfc3339(start_time_str)
                        .map_err(|_| AppError::SerializationError("AI provided invalid start_time format".to_string()))?
                        .with_timezone(&Utc);
                    Ok(TimeScope::Historical(start_time))
                } else {
                    // AI fallback for historical context
                    let historical_time = Utc::now() - Duration::days(7);
                    Ok(TimeScope::Historical(historical_time))
                }
            }
            "Range" => {
                let start_time_str = time_value.get("start_time")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::SerializationError("AI didn't provide start_time for Range".to_string()))?;
                let end_time_str = time_value.get("end_time")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::SerializationError("AI didn't provide end_time for Range".to_string()))?;
                
                let start_time = DateTime::parse_from_rfc3339(start_time_str)
                    .map_err(|_| AppError::SerializationError("AI provided invalid start_time format".to_string()))?
                    .with_timezone(&Utc);
                let end_time = DateTime::parse_from_rfc3339(end_time_str)
                    .map_err(|_| AppError::SerializationError("AI provided invalid end_time format".to_string()))?
                    .with_timezone(&Utc);
                
                Ok(TimeScope::Range(start_time, end_time))
            }
            _ => Err(AppError::SerializationError(format!("AI provided invalid time_scope type: {}", scope_type))),
        }
    }

    /// Parse AI narrative time scope with more flexibility
    fn parse_ai_narrative_time_scope(&self, time_value: &serde_json::Value) -> Result<TimeScope, AppError> {
        let scope_type = time_value.get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::SerializationError("AI didn't specify narrative time_scope type".to_string()))?;

        match scope_type {
            "Current" => Ok(TimeScope::Current),
            "AllTime" | "All" => Ok(TimeScope::AllTime), // Support both for backward compatibility
            "Recent" => {
                // AI determines duration based on narrative context
                let duration_hours = time_value.get("duration_hours")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(24.0); // AI default
                Ok(TimeScope::Recent(Duration::hours(duration_hours as i64)))
            }
            "Historical" => {
                if let Some(start_time_str) = time_value.get("start_time").and_then(|v| v.as_str()) {
                    let start_time = DateTime::parse_from_rfc3339(start_time_str)
                        .map_err(|_| AppError::SerializationError("AI provided invalid historical time format".to_string()))?
                        .with_timezone(&Utc);
                    Ok(TimeScope::Historical(start_time))
                } else {
                    // AI narrative fallback - reasonable historical context
                    let historical_time = Utc::now() - Duration::days(7);
                    Ok(TimeScope::Historical(historical_time))
                }
            }
            "Range" => {
                let start_time_str = time_value.get("start_time")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::SerializationError("AI didn't provide start_time for narrative Range".to_string()))?;
                let end_time_str = time_value.get("end_time")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::SerializationError("AI didn't provide end_time for narrative Range".to_string()))?;
                
                let start_time = DateTime::parse_from_rfc3339(start_time_str)
                    .map_err(|_| AppError::SerializationError("AI provided invalid range start_time".to_string()))?
                    .with_timezone(&Utc);
                let end_time = DateTime::parse_from_rfc3339(end_time_str)
                    .map_err(|_| AppError::SerializationError("AI provided invalid range end_time".to_string()))?
                    .with_timezone(&Utc);
                
                Ok(TimeScope::Range(start_time, end_time))
            }
            _ => Err(AppError::SerializationError(format!("AI provided invalid narrative time_scope: {}", scope_type))),
        }
    }
}

/// Get JSON schema for intent detection output
fn get_intent_detection_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "intent_type": {
                "type": "string",
                "enum": [
                    "CausalAnalysis",
                    "RelationshipQuery",
                    "StateInquiry",
                    "TemporalAnalysis",
                    "SpatialAnalysis",
                    "PredictiveQuery",
                    "NarrativeGeneration",
                    "ComparisonQuery"
                ],
                "description": "The detected intent type"
            },
            "focus_entities": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "entity_type": {"type": "string"},
                        "priority": {"type": "number"},
                        "required": {"type": "boolean"}
                    },
                    "required": ["name"]
                }
            },
            "time_scope": {
                "type": "object",
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": ["Current", "Recent", "Historical", "AllTime", "Range"]
                    },
                    "duration_hours": {"type": "number"},
                    "start_time": {"type": "string"},
                    "end_time": {"type": "string"}
                }
            },
            "spatial_scope": {
                "type": "object",
                "properties": {
                    "location_name": {"type": "string"},
                    "radius": {"type": "number"},
                    "include_contained": {"type": "boolean"}
                }
            },
            "reasoning_depth": {
                "type": "string",
                "enum": ["Surface", "Moderate", "Deep"]
            },
            "context_priorities": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["Character", "Location", "Event", "Relationship", "Item", "System"]
                }
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0
            }
        },
        "required": [
            "intent_type",
            "focus_entities",
            "time_scope",
            "reasoning_depth",
            "context_priorities",
            "confidence"
        ]
    })
}

/// Get JSON schema for narrative intent output
fn get_narrative_intent_schema() -> JsonValue {
    json!({
        "type": "object",
        "properties": {
            "narrative_analysis": {
                "type": "string",
                "description": "AI-driven analysis of the narrative situation"
            },
            "context_needs": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Context requirements for this narrative moment"
            },
            "scene_context": {
                "type": "object",
                "additionalProperties": true,
                "description": "Scene context information from AI interpretation"
            },
            "focus_entities": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "entity_type": {"type": "string"},
                        "priority": {"type": "number"},
                        "required": {"type": "boolean"}
                    },
                    "required": ["name"]
                }
            },
            "time_scope": {
                "type": "object",
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": ["Current", "Recent", "Historical", "AllTime", "Range"]
                    },
                    "duration_hours": {"type": "number"},
                    "start_time": {"type": "string"},
                    "end_time": {"type": "string"}
                }
            },
            "spatial_scope": {
                "type": "object",
                "properties": {
                    "location_name": {"type": "string"},
                    "radius": {"type": "number"},
                    "include_contained": {"type": "boolean"}
                }
            },
            "reasoning_depth": {
                "type": "string",
                "enum": ["Surface", "Moderate", "Deep"]
            },
            "context_priorities": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["Character", "Location", "Event", "Relationship", "Item", "System"]
                }
            },
            "query_strategies": {
                "type": "array",
                "items": {"type": "string"},
                "description": "AI-suggested query strategies"
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0
            }
        },
        "required": [
            "narrative_analysis",
            "context_needs",
            "scene_context",
            "focus_entities",
            "time_scope",
            "reasoning_depth",
            "context_priorities",
            "query_strategies",
            "confidence"
        ]
    })
}