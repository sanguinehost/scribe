use std::sync::Arc;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use tracing::{info, debug, instrument};

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

/// New flexible narrative intent structure for open-ended AI analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NarrativeIntent {
    /// Open-ended AI analysis of the narrative situation and user's intent
    pub narrative_analysis: String,
    /// What specific context the AI thinks it needs to fulfill this narrative intent
    pub context_needs: Vec<String>,
    /// Scene context information for narrative understanding
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
    /// Dynamic query strategies the AI suggests for gathering context
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
}

pub struct IntentDetectionService {
    ai_client: Arc<dyn AiClient>,
}

impl IntentDetectionService {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self { ai_client }
    }

    #[instrument(skip(self), fields(query_len = user_query.len()))]
    pub async fn detect_intent(
        &self,
        user_query: &str,
        conversation_context: Option<&str>,
    ) -> Result<QueryIntent, AppError> {
        let prompt = self.build_intent_detection_prompt(user_query, conversation_context);
        
        info!("Detecting intent for query: {}", user_query);
        
        // Build ChatRequest using the AI client interface
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1000)
            .with_temperature(0.1);
        
        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-lite-preview-06-17", // Use Flash-Lite for cost-effective intent detection
            chat_request,
            Some(chat_options),
        ).await?;

        // Extract text content from ChatResponse
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

        self.parse_intent_response(&response_text)
    }

    /// New method for open-ended narrative intent detection
    #[instrument(skip(self), fields(query_len = user_query.len()))]
    pub async fn detect_narrative_intent(
        &self,
        user_query: &str,
        conversation_context: Option<&str>,
    ) -> Result<NarrativeIntent, AppError> {
        let prompt = self.build_narrative_intent_prompt(user_query, conversation_context);
        
        info!("Detecting narrative intent for query: {}", user_query);
        
        // Build ChatRequest using the AI client interface
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1500) // More tokens for open-ended analysis
            .with_temperature(0.2); // Slightly higher for more creative narrative understanding
        
        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-lite-preview-06-17", // Use Flash-Lite for cost-effective analysis
            chat_request,
            Some(chat_options),
        ).await?;

        // Extract text content from ChatResponse
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

        self.parse_narrative_intent_response(&response_text)
    }

    fn build_intent_detection_prompt(&self, query: &str, context: Option<&str>) -> String {
        let context_section = context.map_or(String::new(), |c| format!("Conversation Context:\n{}\n\n", c));
        
        format!(r#"You are an expert query intent analyzer for a narrative AI system. Analyze the user's query and determine their intent, focus entities, and context requirements.

{}User Query: "{}"

Analyze this query and respond with a JSON object containing:
1. intent_type: One of [CausalAnalysis, RelationshipQuery, StateInquiry, TemporalAnalysis, SpatialAnalysis, PredictiveQuery, NarrativeGeneration, ComparisonQuery]
2. focus_entities: Array of {{name: string, type?: string, priority: 0.0-1.0, required: boolean}}
3. time_scope: {{type: "Current"|"Recent"|"Historical"|"Range"|"AllTime", duration_hours?: number, start_time?: ISO8601, end_time?: ISO8601}}
4. spatial_scope?: {{location_name?: string, radius?: number, include_contained: boolean}}
5. reasoning_depth: "Surface"|"Analytical"|"Causal"|"Deep"
6. context_priorities: Array of [Entities, Relationships, RecentEvents, SpatialContext, CausalChains, TemporalState] in order of importance
7. confidence: 0.0-1.0

Examples:
- "What caused Luke to leave Tatooine?" → CausalAnalysis, focus_entities: [{{name: "Luke", priority: 1.0, required: true}}], reasoning_depth: "Causal"
- "Who is in the cantina right now?" → SpatialAnalysis + StateInquiry, spatial_scope: {{location_name: "cantina"}}, time_scope: "Current"
- "How do Vader and Obi-Wan feel about each other?" → RelationshipQuery, focus_entities: [{{name: "Vader", priority: 1.0}}, {{name: "Obi-Wan", priority: 1.0}}]

Respond with only the JSON object, no other text:"#, context_section, query)
    }

    /// Build prompt for open-ended narrative intent analysis  
    fn build_narrative_intent_prompt(&self, query: &str, context: Option<&str>) -> String {
        let context_section = context.map_or(String::new(), |c| format!("Recent Conversation Context:\n{}\n\n", c));
        
        format!(r#"You are an expert narrative AI assistant analyzing user input for an interactive storytelling system. Your job is to understand the narrative intent behind the user's action and determine what context you need to provide an engaging, contextually-rich response.

{}User's Narrative Action: "{}"

Analyze this narrative input and respond with a JSON object containing your analysis and context requirements:

1. "narrative_analysis": A detailed string explaining what the user is trying to accomplish narratively (scene transition, character development, action sequence, emotional moment, etc.)

2. "context_needs": Array of specific context requirements you need, such as:
   - "Character's current emotional state and recent interactions"
   - "Location details and environmental atmosphere" 
   - "Recent events affecting this character or situation"
   - "Relationship dynamics between involved characters"
   - "Historical background for locations or situations"
   - "Character abilities, skills, or equipment relevant to the action"

3. "scene_context": Object with narrative scene analysis:
   - "current_scene_type": Type of scene (e.g., "combat_encounter", "character_dialogue", "exploration_discovery", "family_domestic", "political_intrigue")
   - "narrative_goal": What the scene aims to accomplish (e.g., "character_development", "plot_advancement", "world_building", "tension_building")
   - "emotional_tone": Current emotional atmosphere (e.g., "tense_confrontation", "warm_intimate", "mysterious_foreboding", "high_action_excitement")
   - "relationship_focus": Key relationship dynamics at play

4. "focus_entities": Array of entities/characters important to this moment:
   - "name": Entity name
   - "priority": 0.0-1.0 importance score
   - "required": Boolean if absolutely necessary for context
   - "context_role": Their role in this narrative moment (e.g., "primary_character", "relationship_target", "environmental_element", "threat_source")

5. "time_scope": Temporal context needed:
   - "type": "Current", "Recent", "Historical", "Range", or "AllTime"  
   - "narrative_timeframe": How time relates to narrative (e.g., "immediate_scene_transition", "character_backstory_relevant", "recent_consequences")
   - Additional time parameters if needed (duration_hours, specific dates)

6. "spatial_scope": If location/environment matters:
   - "location_name": Specific location if relevant
   - "include_contained": Boolean for sub-locations
   - "spatial_narrative": How space affects the narrative (e.g., "intimate_private_space", "tactical_combat_environment", "mysterious_archaeological_site")

7. "reasoning_depth": "Surface", "Analytical", "Causal", or "Deep" - how much analysis is needed

8. "context_priorities": Array prioritizing what context types are most important: ["Entities", "Relationships", "RecentEvents", "SpatialContext", "CausalChains", "TemporalState"]

9. "query_strategies": Array of specific query approaches to gather the needed context:
   - "get_entity_emotional_state"
   - "find_recent_relationship_interactions"
   - "retrieve_location_atmospheric_details"
   - "analyze_combat_readiness_status"
   - "check_character_skills_equipment"
   - "get_historical_location_significance"
   - Other specific strategies based on narrative needs

10. "confidence": 0.0-1.0 confidence in this analysis

Focus on understanding the NARRATIVE INTENT and STORYTELLING NEEDS rather than categorizing into rigid types. Think about what context would make the AI's response most engaging and contextually rich for this specific narrative moment.

Examples:
- User: "Lumiya sighs and goes to check on her children" → Family scene transition requiring emotional state, children's activities, domestic setting details
- User: "Kael draws his blaster as enemies surround him" → Combat scene requiring tactical environment, threat assessment, equipment status
- User: "She examines the ancient symbols carved into the stone" → Discovery scene requiring historical context, environmental atmosphere, character knowledge

Respond with only the JSON object:"#, context_section, query)
    }

    /// Parse the open-ended narrative intent response
    fn parse_narrative_intent_response(&self, response: &str) -> Result<NarrativeIntent, AppError> {
        let cleaned = response.trim();
        
        // Parse as JSON value first
        let json_value: serde_json::Value = serde_json::from_str(cleaned)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse narrative intent response JSON: {}", e)))?;
        
        // Extract narrative analysis
        let narrative_analysis = json_value["narrative_analysis"]
            .as_str()
            .ok_or_else(|| AppError::SerializationError("Missing narrative_analysis".to_string()))?
            .to_string();
        
        // Extract context needs
        let context_needs = json_value["context_needs"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        
        // Extract scene context as HashMap
        let scene_context = json_value["scene_context"]
            .as_object()
            .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_else(HashMap::new);
        
        // Parse focus entities with the new context_role field
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
        
        // Parse time scope with narrative-aware logic
        let time_scope = self.parse_narrative_time_scope(&json_value["time_scope"])?;
        
        // Parse spatial scope with new fields
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
        
        // Parse reasoning depth
        let reasoning_depth = match json_value["reasoning_depth"].as_str() {
            Some("Surface") => ReasoningDepth::Surface,
            Some("Analytical") => ReasoningDepth::Analytical,
            Some("Causal") => ReasoningDepth::Causal,
            Some("Deep") => ReasoningDepth::Deep,
            _ => ReasoningDepth::Analytical, // Default fallback
        };
        
        // Parse context priorities
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
                    _ => None,
                }
            })
            .collect();
        
        // Parse query strategies
        let query_strategies = json_value["query_strategies"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        
        // Parse confidence
        let confidence = json_value["confidence"]
            .as_f64()
            .unwrap_or(0.5) as f32;
        
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

    fn parse_intent_response(&self, response: &str) -> Result<QueryIntent, AppError> {
        let cleaned = response.trim();
        
        // First parse as a generic JSON value to handle the custom deserialization
        let json_value: serde_json::Value = serde_json::from_str(cleaned)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse intent response JSON: {}", e)))?;
        
        // Convert time_scope with custom logic
        let time_scope = self.parse_time_scope(&json_value["time_scope"])?;
        
        // Convert spatial_scope if present
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

        // Parse focus entities
        let focus_entities = json_value["focus_entities"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|entity_value| {
                Some(EntityFocus {
                    name: entity_value.get("name")?.as_str()?.to_string(),
                    entity_type: entity_value.get("type")
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

        // Parse context priorities
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
                    _ => None,
                }
            })
            .collect();

        // Parse intent type
        let intent_type = match json_value["intent_type"].as_str() {
            Some("CausalAnalysis") => IntentType::CausalAnalysis,
            Some("RelationshipQuery") => IntentType::RelationshipQuery,
            Some("StateInquiry") => IntentType::StateInquiry,
            Some("TemporalAnalysis") => IntentType::TemporalAnalysis,
            Some("SpatialAnalysis") => IntentType::SpatialAnalysis,
            Some("PredictiveQuery") => IntentType::PredictiveQuery,
            Some("NarrativeGeneration") => IntentType::NarrativeGeneration,
            Some("ComparisonQuery") => IntentType::ComparisonQuery,
            _ => return Err(AppError::SerializationError("Invalid intent_type".to_string())),
        };

        // Parse reasoning depth
        let reasoning_depth = match json_value["reasoning_depth"].as_str() {
            Some("Surface") => ReasoningDepth::Surface,
            Some("Analytical") => ReasoningDepth::Analytical,
            Some("Causal") => ReasoningDepth::Causal,
            Some("Deep") => ReasoningDepth::Deep,
            _ => return Err(AppError::SerializationError("Invalid reasoning_depth".to_string())),
        };

        Ok(QueryIntent {
            intent_type,
            focus_entities,
            time_scope,
            spatial_scope,
            reasoning_depth,
            context_priorities,
            confidence: json_value["confidence"]
                .as_f64()
                .unwrap_or(0.5) as f32,
        })
    }

    /// Parse time scope for narrative intent (more flexible than rigid analysis)
    fn parse_narrative_time_scope(&self, time_value: &serde_json::Value) -> Result<TimeScope, AppError> {
        let scope_type = time_value.get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::SerializationError("Missing time_scope type".to_string()))?;

        match scope_type {
            "Current" => Ok(TimeScope::Current),
            "AllTime" => Ok(TimeScope::AllTime),
            "Recent" => {
                // For narrative, default to 24 hours if not specified
                let duration_hours = time_value.get("duration_hours")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(24.0);
                Ok(TimeScope::Recent(Duration::hours(duration_hours as i64)))
            }
            "Historical" => {
                // For narrative analysis, Historical can be more flexible
                // If we have a specific start_time, use it; otherwise use a reasonable default
                if let Some(start_time_str) = time_value.get("start_time").and_then(|v| v.as_str()) {
                    let start_time = DateTime::parse_from_rfc3339(start_time_str)
                        .map_err(|_| AppError::SerializationError("Invalid start_time format".to_string()))?
                        .with_timezone(&Utc);
                    Ok(TimeScope::Historical(start_time))
                } else {
                    // For narrative purposes, Historical means "background/past context"
                    // Default to 7 days ago as a reasonable historical scope
                    let historical_time = Utc::now() - Duration::days(7);
                    Ok(TimeScope::Historical(historical_time))
                }
            }
            "Range" => {
                let start_time_str = time_value.get("start_time")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::SerializationError("Missing start_time for Range scope".to_string()))?;
                let end_time_str = time_value.get("end_time")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::SerializationError("Missing end_time for Range scope".to_string()))?;
                
                let start_time = DateTime::parse_from_rfc3339(start_time_str)
                    .map_err(|_| AppError::SerializationError("Invalid start_time format".to_string()))?
                    .with_timezone(&Utc);
                let end_time = DateTime::parse_from_rfc3339(end_time_str)
                    .map_err(|_| AppError::SerializationError("Invalid end_time format".to_string()))?
                    .with_timezone(&Utc);
                
                Ok(TimeScope::Range(start_time, end_time))
            }
            _ => Err(AppError::SerializationError(format!("Invalid time_scope type: {}", scope_type))),
        }
    }

    fn parse_time_scope(&self, time_value: &serde_json::Value) -> Result<TimeScope, AppError> {
        let scope_type = time_value.get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::SerializationError("Missing time_scope type".to_string()))?;

        match scope_type {
            "Current" => Ok(TimeScope::Current),
            "AllTime" => Ok(TimeScope::AllTime),
            "Recent" => {
                let duration_hours = time_value.get("duration_hours")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(24.0);
                Ok(TimeScope::Recent(Duration::hours(duration_hours as i64)))
            }
            "Historical" => {
                let start_time_str = time_value.get("start_time")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::SerializationError("Missing start_time for Historical scope".to_string()))?;
                let start_time = DateTime::parse_from_rfc3339(start_time_str)
                    .map_err(|_| AppError::SerializationError("Invalid start_time format".to_string()))?
                    .with_timezone(&Utc);
                Ok(TimeScope::Historical(start_time))
            }
            "Range" => {
                let start_time_str = time_value.get("start_time")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::SerializationError("Missing start_time for Range scope".to_string()))?;
                let end_time_str = time_value.get("end_time")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AppError::SerializationError("Missing end_time for Range scope".to_string()))?;
                
                let start_time = DateTime::parse_from_rfc3339(start_time_str)
                    .map_err(|_| AppError::SerializationError("Invalid start_time format".to_string()))?
                    .with_timezone(&Utc);
                let end_time = DateTime::parse_from_rfc3339(end_time_str)
                    .map_err(|_| AppError::SerializationError("Invalid end_time format".to_string()))?
                    .with_timezone(&Utc);
                
                Ok(TimeScope::Range(start_time, end_time))
            }
            _ => Err(AppError::SerializationError(format!("Invalid time_scope type: {}", scope_type))),
        }
    }
}