use std::sync::Arc;
use serde::{Serialize, Deserialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use tracing::{info, instrument, debug};

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
    /// AI-generated optimization hints for the execution phase
    pub optimization_hints: Vec<String>,
    /// AI confidence in the plan effectiveness
    pub plan_confidence: f32,
    /// Alternative strategies considered by AI
    pub alternative_strategies: Vec<AlternativeStrategy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternativeStrategy {
    pub strategy: QueryStrategy,
    pub reasoning: String,
    pub trade_offs: String,
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
    // New AI-driven strategies
    AdaptiveNarrativeStrategy,
    EmergentPatternDiscovery,
    ContextualRelevanceOptimization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedQuery {
    pub query_type: PlannedQueryType,
    pub priority: f32,
    pub parameters: HashMap<String, serde_json::Value>,
    pub estimated_tokens: Option<u32>,
    pub dependencies: Vec<String>,
    /// AI-generated reasoning for why this query is important
    pub query_reasoning: Option<String>,
    /// Expected information yield (AI prediction)
    pub expected_yield: Option<f32>,
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
        info!("Using Flash for AI-driven query strategy planning for intent: {:?}", intent.intent_type);
        
        let prompt = self.build_flash_strategy_planning_prompt(intent, token_budget);
        
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(2200)
            .with_temperature(0.15); // Low temperature for consistent strategic planning
        
        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-preview-06-17", // Full Flash for sophisticated planning
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

        self.parse_flash_strategy_response(&response_text)
    }

    /// AI-driven adaptive query planning with narrative focus
    #[instrument(skip(self), fields(narrative_focus))]
    pub async fn plan_narrative_query_strategy(
        &self,
        intent: &QueryIntent,
        narrative_focus: &str,
        token_budget: u32,
    ) -> Result<QueryExecutionPlan, AppError> {
        info!("Using Flash for narrative-focused AI query planning: {}", narrative_focus);
        
        let prompt = self.build_narrative_strategy_prompt(intent, narrative_focus, token_budget);
        
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(2500)
            .with_temperature(0.25); // Slightly higher for creative narrative planning
        
        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-preview-06-17", // Full Flash for narrative intelligence
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

        self.parse_flash_strategy_response(&response_text)
    }

    fn build_flash_strategy_planning_prompt(&self, intent: &QueryIntent, token_budget: u32) -> String {
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

        format!(r#"You are an advanced AI query strategy planner for a narrative intelligence system. Your task is to design optimal query execution plans that maximize narrative coherence and information yield while respecting token constraints.

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
- Must balance efficiency with narrative completeness
- Consider query dependencies and information flow
- Optimize for the specific intent type

ADVANCED QUERY PLANNING:
Think strategically about:
1. Information architecture - what data builds on what
2. Narrative flow - how queries support storytelling
3. Token economics - maximize value per token
4. Dependency chains - what must come before what
5. Alternative approaches - what other strategies could work

AVAILABLE QUERY TYPES & THEIR NARRATIVE PURPOSES:
Entity Queries:
- EntityEvents: Character actions and history
- EntityCurrentState: Present moment snapshot
- EntityStates: State evolution over time
- ActiveEntities: Who's actively involved

Relationship Queries:
- EntityRelationships: Social/power dynamics
- SharedEvents: Common experiences

Causal Queries:
- CausalChain: Cause-and-effect narratives
- CausalFactors: Contributing influences

Spatial Queries:
- SpatialEntities: Scene setting and presence

Temporal Queries:
- TimelineEvents: Chronological narrative
- StateTransitions: Change moments
- RecentEvents: Immediate context

Advanced Queries:
- HistoricalParallels: Pattern recognition
- NarrativeThreads: Story continuity
- Chronicle/Lorebook queries: World knowledge

STRATEGY OPTIONS WITH AI REASONING:
- CausalChainTraversal: Deep causality exploration
- SpatialContextMapping: Environmental understanding
- RelationshipNetworkTraversal: Social dynamics mapping
- TemporalStateReconstruction: Time-based narrative
- CausalProjection: Future possibility space
- NarrativeContextAssembly: Holistic story building
- StateSnapshot: Current moment focus
- ComparativeAnalysis: Contrast and comparison
- AdaptiveNarrativeStrategy: AI-driven flexible approach
- EmergentPatternDiscovery: Finding hidden connections
- ContextualRelevanceOptimization: Smart context pruning

RESPOND WITH JSON:
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
            }},
            "estimated_tokens": <optional_number>,
            "dependencies": ["<dependent_query_type>"],
            "query_reasoning": "<why this query matters for the narrative>",
            "expected_yield": 0.0-1.0
        }}
    ],
    "context_budget": <estimated_tokens_needed>,
    "execution_order": ["query_type1", "query_type2"],
    "reasoning": "<comprehensive explanation of strategy choice and expected narrative value>",
    "optimization_hints": [
        "<hint about execution optimization>",
        "<hint about result processing>"
    ],
    "plan_confidence": 0.0-1.0,
    "alternative_strategies": [
        {{
            "strategy": "<alternative_strategy_name>",
            "reasoning": "<why this could work>",
            "trade_offs": "<what we gain/lose with this approach>"
        }}
    ]
}}

Think deeply about the narrative implications of each query choice. Consider:
- Will this query sequence tell a coherent story?
- Are we gathering context that enriches understanding?
- Does the order create natural narrative flow?
- Are we being efficient without losing essential context?

For a token budget of {}, you should plan {} queries.

Respond with only the JSON object:"#, 
            intent.intent_type,
            focus_entities,
            time_scope_desc,
            spatial_scope_desc,
            intent.reasoning_depth,
            intent.context_priorities,
            intent.confidence,
            token_budget,
            token_budget,
            if token_budget < 5000 { "2-4" } 
            else if token_budget < 10000 { "3-6" } 
            else { "4-8" }
        )
    }

    fn build_narrative_strategy_prompt(&self, intent: &QueryIntent, narrative_focus: &str, token_budget: u32) -> String {
        format!(r#"You are an expert narrative strategist for an AI storytelling system. Design a query execution plan specifically optimized for the following narrative moment:

NARRATIVE FOCUS:
"{}"

CURRENT INTENT:
{:?}

TOKEN BUDGET: {} tokens

NARRATIVE PLANNING TASK:
Create a query plan that serves this specific narrative moment. Consider:
1. **Dramatic Needs**: What information creates tension or resolution?
2. **Character Development**: What reveals character growth or conflict?
3. **World Building**: What enriches the setting and atmosphere?
4. **Pacing**: What information flow best serves the narrative rhythm?
5. **Emotional Resonance**: What data enhances emotional impact?

NARRATIVE-FIRST STRATEGIES:
- NarrativeContextAssembly: Holistic story-focused gathering
- EmergentPatternDiscovery: Finding narrative threads
- AdaptiveNarrativeStrategy: AI-guided narrative optimization
- ChronicleNarrativeMapping: Story-to-world connections
- ContextualRelevanceOptimization: Narrative-driven pruning

Design queries that don't just gather data, but craft experience.

RESPOND WITH JSON (same structure as before, but optimize everything for narrative impact):"#,
            narrative_focus,
            intent,
            token_budget
        )
    }

    fn parse_flash_strategy_response(&self, response: &str) -> Result<QueryExecutionPlan, AppError> {
        let cleaned = response.trim();
        
        let json_value: JsonValue = serde_json::from_str(cleaned)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse Flash strategy response: {}", e)))?;
        
        // Parse primary strategy with new AI-driven options
        let primary_strategy = match json_value["primary_strategy"].as_str() {
            Some("CausalChainTraversal") => QueryStrategy::CausalChainTraversal,
            Some("SpatialContextMapping") => QueryStrategy::SpatialContextMapping,
            Some("RelationshipNetworkTraversal") => QueryStrategy::RelationshipNetworkTraversal,
            Some("TemporalStateReconstruction") => QueryStrategy::TemporalStateReconstruction,
            Some("CausalProjection") => QueryStrategy::CausalProjection,
            Some("NarrativeContextAssembly") => QueryStrategy::NarrativeContextAssembly,
            Some("StateSnapshot") => QueryStrategy::StateSnapshot,
            Some("ComparativeAnalysis") => QueryStrategy::ComparativeAnalysis,
            Some("ChronicleNarrativeMapping") => QueryStrategy::ChronicleNarrativeMapping,
            Some("ChronicleThematicAnalysis") => QueryStrategy::ChronicleThematicAnalysis,
            Some("ChronicleTimelineReconstruction") => QueryStrategy::ChronicleTimelineReconstruction,
            Some("LorebookContextualRetrieval") => QueryStrategy::LorebookContextualRetrieval,
            Some("LorebookConceptualMapping") => QueryStrategy::LorebookConceptualMapping,
            Some("LorebookCulturalContext") => QueryStrategy::LorebookCulturalContext,
            Some("AdaptiveNarrativeStrategy") => QueryStrategy::AdaptiveNarrativeStrategy,
            Some("EmergentPatternDiscovery") => QueryStrategy::EmergentPatternDiscovery,
            Some("ContextualRelevanceOptimization") => QueryStrategy::ContextualRelevanceOptimization,
            _ => QueryStrategy::NarrativeContextAssembly, // Default fallback
        };

        // Parse queries with enhanced fields
        let queries = json_value["queries"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|query_value| {
                let query_type = match query_value["query_type"].as_str()? {
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

                let priority = query_value["priority"]
                    .as_f64()
                    .unwrap_or(0.5)
                    .clamp(0.0, 1.0) as f32;

                let parameters = query_value["parameters"]
                    .as_object()
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
                    estimated_tokens: query_value["estimated_tokens"]
                        .as_u64()
                        .map(|v| v as u32),
                    dependencies: query_value["dependencies"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str())
                                .map(|s| s.to_string())
                                .collect()
                        })
                        .unwrap_or_default(),
                    query_reasoning: query_value["query_reasoning"]
                        .as_str()
                        .map(|s| s.to_string()),
                    expected_yield: query_value["expected_yield"]
                        .as_f64()
                        .map(|v| v.clamp(0.0, 1.0) as f32),
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

        // Parse optimization hints
        let optimization_hints = json_value["optimization_hints"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_string())
            .collect();

        // Parse alternative strategies
        let alternative_strategies = json_value["alternative_strategies"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|alt| {
                let strategy = match alt["strategy"].as_str()? {
                    "CausalChainTraversal" => QueryStrategy::CausalChainTraversal,
                    "SpatialContextMapping" => QueryStrategy::SpatialContextMapping,
                    "RelationshipNetworkTraversal" => QueryStrategy::RelationshipNetworkTraversal,
                    "TemporalStateReconstruction" => QueryStrategy::TemporalStateReconstruction,
                    "CausalProjection" => QueryStrategy::CausalProjection,
                    "NarrativeContextAssembly" => QueryStrategy::NarrativeContextAssembly,
                    "StateSnapshot" => QueryStrategy::StateSnapshot,
                    "ComparativeAnalysis" => QueryStrategy::ComparativeAnalysis,
                    "AdaptiveNarrativeStrategy" => QueryStrategy::AdaptiveNarrativeStrategy,
                    "EmergentPatternDiscovery" => QueryStrategy::EmergentPatternDiscovery,
                    "ContextualRelevanceOptimization" => QueryStrategy::ContextualRelevanceOptimization,
                    _ => return None,
                };

                Some(AlternativeStrategy {
                    strategy,
                    reasoning: alt["reasoning"].as_str()?.to_string(),
                    trade_offs: alt["trade_offs"].as_str()?.to_string(),
                })
            })
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
                .unwrap_or("AI strategy planning applied")
                .to_string(),
            optimization_hints,
            plan_confidence: json_value["plan_confidence"]
                .as_f64()
                .unwrap_or(0.85)
                .clamp(0.0, 1.0) as f32,
            alternative_strategies,
        })
    }
}