use std::sync::Arc;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tracing::{info, instrument};

use crate::{
    llm::AiClient,
    errors::AppError,
    services::intent_detection_service::QueryIntent,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryExecutionPlan {
    pub primary_strategy: QueryStrategy,
    pub queries: Vec<PlannedQuery>,
    pub context_budget: u32,
    pub execution_order: Vec<String>,
    pub reasoning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QueryStrategy {
    CausalChainTraversal,
    SpatialContextMapping,
    RelationshipNetworkTraversal,
    TemporalStateReconstruction,
    CausalProjection,
    NarrativeContextAssembly,
    StateSnapshot,
    ComparativeAnalysis,
    // Chronicle-focused strategies
    ChronicleNarrativeMapping,
    ChronicleThematicAnalysis,
    ChronicleTimelineReconstruction,
    // Lorebook-focused strategies
    LorebookContextualRetrieval,
    LorebookConceptualMapping,
    LorebookCulturalContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedQuery {
    pub query_type: PlannedQueryType,
    pub priority: f32,
    pub parameters: HashMap<String, serde_json::Value>,
    pub estimated_tokens: Option<u32>,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PlannedQueryType {
    // Entity-focused queries
    EntityEvents,
    EntityCurrentState,
    EntityStates,
    ActiveEntities,
    
    // Relationship queries
    EntityRelationships,
    SharedEvents,
    
    // Causal queries
    CausalChain,
    CausalFactors,
    
    // Spatial queries
    SpatialEntities,
    
    // Temporal queries
    TimelineEvents,
    StateTransitions,
    RecentEvents,
    
    // Predictive queries
    HistoricalParallels,
    
    // Narrative queries
    NarrativeThreads,
    
    // Chronicle queries
    ChronicleEvents,
    ChronicleTimeline,
    ChronicleThemes,
    RelatedChronicles,
    
    // Lorebook queries
    LorebookEntries,
    LorebookConcepts,
    LorebookCharacters,
    LorebookLocations,
    LorebookContext,
    
    // Entity creation queries
    MissingEntities,
}

pub struct QueryStrategyPlanner {
    ai_client: Arc<dyn AiClient>,
}

impl QueryStrategyPlanner {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self { ai_client }
    }

    #[instrument(skip(self), fields(intent_type = ?intent.intent_type, token_budget))]
    pub async fn plan_query_strategy(
        &self,
        intent: &QueryIntent,
        token_budget: u32,
    ) -> Result<QueryExecutionPlan, AppError> {
        let prompt = self.build_strategy_planning_prompt(intent, token_budget);
        
        info!("Planning query strategy for intent: {:?}", intent.intent_type);
        
        // Build ChatRequest using the AI client interface
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(2000)
            .with_temperature(0.2); // Low temperature for consistent planning
        
        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-lite-preview-06-17", // Use Flash-Lite for cost-effective strategy planning
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

        self.parse_strategy_response(&response_text)
    }

    fn build_strategy_planning_prompt(&self, intent: &QueryIntent, token_budget: u32) -> String {
        let focus_entities = intent.focus_entities
            .iter()
            .map(|e| format!("{} (priority: {}, required: {})", e.name, e.priority, e.required))
            .collect::<Vec<_>>()
            .join(", ");

        let time_scope_desc = match &intent.time_scope {
            crate::services::intent_detection_service::TimeScope::Current => "Current time".to_string(),
            crate::services::intent_detection_service::TimeScope::Recent(duration) => {
                format!("Recent {} hours", duration.num_hours())
            }
            crate::services::intent_detection_service::TimeScope::Historical(dt) => {
                format!("Historical from {}", dt.format("%Y-%m-%d"))
            }
            crate::services::intent_detection_service::TimeScope::Range(start, end) => {
                format!("Range from {} to {}", start.format("%Y-%m-%d"), end.format("%Y-%m-%d"))
            }
            crate::services::intent_detection_service::TimeScope::AllTime => "All time".to_string(),
        };

        let spatial_scope_desc = intent.spatial_scope
            .as_ref()
            .map(|s| format!("Location: {:?}, Include contained: {}", s.location_name, s.include_contained))
            .unwrap_or_else(|| "No spatial constraints".to_string());

        format!(r#"You are a query strategy planner for an ECS-based narrative AI system. Plan the optimal set of ECS queries to answer the user's intent.

INTENT ANALYSIS:
- Intent Type: {:?}
- Focus Entities: {}
- Time Scope: {}
- Spatial Scope: {}
- Reasoning Depth: {:?}
- Context Priorities: {:?}
- Confidence: {}

CONSTRAINTS:
- Token Budget: {} tokens
- Must be efficient and selective
- Prioritize high-impact queries
- Consider query dependencies

AVAILABLE QUERY TYPES:
Entity Queries: EntityEvents, EntityCurrentState, EntityStates, ActiveEntities
Relationship Queries: EntityRelationships, SharedEvents  
Causal Queries: CausalChain, CausalFactors
Spatial Queries: SpatialEntities
Temporal Queries: TimelineEvents, StateTransitions, RecentEvents
Predictive Queries: HistoricalParallels
Narrative Queries: NarrativeThreads
Chronicle Queries: ChronicleEvents, ChronicleTimeline, ChronicleThemes, RelatedChronicles
Lorebook Queries: LorebookEntries, LorebookConcepts, LorebookCharacters, LorebookLocations, LorebookContext
Entity Creation Queries: MissingEntities

STRATEGY OPTIONS:
- CausalChainTraversal: For "what caused X" questions
- SpatialContextMapping: For "who/what is at location Y"
- RelationshipNetworkTraversal: For "how do X and Y relate"
- TemporalStateReconstruction: For "what happened over time"
- CausalProjection: For "what might happen if"
- NarrativeContextAssembly: For story continuation
- StateSnapshot: For current state inquiries
- ComparativeAnalysis: For comparing entities

Respond with a JSON object:
{{
    "primary_strategy": "<strategy_name>",
    "queries": [
        {{
            "query_type": "<query_type>",
            "priority": 0.0-1.0,
            "parameters": {{
                "entity_names": ["name1", "name2"],
                "time_scope": "<scope>",
                "max_results": <number>,
                "<param>": "<value>"
            }}
        }}
    ],
    "context_budget": <estimated_tokens_needed>,
    "execution_order": ["query_type1", "query_type2"],
    "reasoning": "Brief explanation of strategy choice"
}}

Examples:
- For CausalAnalysis: Use CausalChainTraversal with EntityEvents + CausalChain queries
- For SpatialAnalysis: Use SpatialContextMapping with SpatialEntities + EntityStates queries  
- For RelationshipQuery: Use RelationshipNetworkTraversal with EntityRelationships + SharedEvents queries
- For PredictiveQuery: Use CausalProjection with EntityCurrentState + CausalFactors + HistoricalParallels queries

Optimize for the token budget - fewer queries for smaller budgets, more comprehensive for larger budgets.

Respond with only the JSON object:"#, 
            intent.intent_type,
            focus_entities,
            time_scope_desc,
            spatial_scope_desc,
            intent.reasoning_depth,
            intent.context_priorities,
            intent.confidence,
            token_budget
        )
    }

    fn parse_strategy_response(&self, response: &str) -> Result<QueryExecutionPlan, AppError> {
        let cleaned = response.trim();
        
        // Parse JSON response
        let json_value: serde_json::Value = serde_json::from_str(cleaned)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse strategy response JSON: {}", e)))?;
        
        // Parse primary strategy
        let primary_strategy = match json_value["primary_strategy"].as_str() {
            Some("CausalChainTraversal") => QueryStrategy::CausalChainTraversal,
            Some("SpatialContextMapping") => QueryStrategy::SpatialContextMapping,
            Some("RelationshipNetworkTraversal") => QueryStrategy::RelationshipNetworkTraversal,
            Some("TemporalStateReconstruction") => QueryStrategy::TemporalStateReconstruction,
            Some("CausalProjection") => QueryStrategy::CausalProjection,
            Some("NarrativeContextAssembly") => QueryStrategy::NarrativeContextAssembly,
            Some("StateSnapshot") => QueryStrategy::StateSnapshot,
            Some("ComparativeAnalysis") => QueryStrategy::ComparativeAnalysis,
            _ => return Err(AppError::SerializationError("Invalid primary_strategy".to_string())),
        };

        // Parse queries
        let queries = json_value["queries"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|query_value| {
                let query_type = match query_value.get("query_type")?.as_str()? {
                    "EntityEvents" => PlannedQueryType::EntityEvents,
                    "EntityCurrentState" => PlannedQueryType::EntityCurrentState,
                    "EntityStates" => PlannedQueryType::EntityStates,
                    "ActiveEntities" => PlannedQueryType::ActiveEntities,
                    "EntityRelationships" => PlannedQueryType::EntityRelationships,
                    "SharedEvents" => PlannedQueryType::SharedEvents,
                    "CausalChain" => PlannedQueryType::CausalChain,
                    "CausalFactors" => PlannedQueryType::CausalFactors,
                    "SpatialEntities" => PlannedQueryType::SpatialEntities,
                    "TimelineEvents" => PlannedQueryType::TimelineEvents,
                    "StateTransitions" => PlannedQueryType::StateTransitions,
                    "RecentEvents" => PlannedQueryType::RecentEvents,
                    "HistoricalParallels" => PlannedQueryType::HistoricalParallels,
                    "NarrativeThreads" => PlannedQueryType::NarrativeThreads,
                    "ChronicleEvents" => PlannedQueryType::ChronicleEvents,
                    "ChronicleTimeline" => PlannedQueryType::ChronicleTimeline,
                    "ChronicleThemes" => PlannedQueryType::ChronicleThemes,
                    "RelatedChronicles" => PlannedQueryType::RelatedChronicles,
                    "LorebookEntries" => PlannedQueryType::LorebookEntries,
                    "LorebookConcepts" => PlannedQueryType::LorebookConcepts,
                    "LorebookCharacters" => PlannedQueryType::LorebookCharacters,
                    "LorebookLocations" => PlannedQueryType::LorebookLocations,
                    "LorebookContext" => PlannedQueryType::LorebookContext,
                    "MissingEntities" => PlannedQueryType::MissingEntities,
                    _ => return None,
                };

                let priority = query_value.get("priority")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.5) as f32;

                // Parse parameters as HashMap
                let parameters = query_value.get("parameters")
                    .and_then(|v| v.as_object())
                    .map(|obj| {
                        obj.iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect()
                    })
                    .unwrap_or_default();

                Some(PlannedQuery {
                    query_type,
                    priority,
                    parameters,
                    estimated_tokens: query_value.get("estimated_tokens")
                        .and_then(|v| v.as_u64())
                        .map(|v| v as u32),
                    dependencies: query_value.get("dependencies")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .map(|s| s.to_string())
                                .collect()
                        })
                        .unwrap_or_default(),
                })
            })
            .collect();

        // Parse execution order
        let execution_order = json_value["execution_order"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect();

        Ok(QueryExecutionPlan {
            primary_strategy,
            queries,
            context_budget: json_value["context_budget"]
                .as_u64()
                .unwrap_or(5000) as u32,
            execution_order,
            reasoning: json_value["reasoning"]
                .as_str()
                .unwrap_or("No reasoning provided")
                .to_string(),
        })
    }
}