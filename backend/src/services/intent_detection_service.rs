use std::sync::Arc;
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