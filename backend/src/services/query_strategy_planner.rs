use std::sync::Arc;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tracing::{info, instrument};
use genai::chat::{ChatOptions, ChatResponseFormat, JsonSchemaSpec};

use crate::{
    llm::AiClient,
    errors::AppError,
    services::{
        intent_detection_service::QueryIntent,
        query_registry::QueryRegistry,
    },
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
    model: String,
}

impl QueryStrategyPlanner {
    pub fn new(ai_client: Arc<dyn AiClient>, model: String) -> Self {
        Self { ai_client, model }
    }
    
    /// Get all available query strategies as strings from the registry
    #[allow(dead_code)]
    fn get_available_strategies() -> Vec<&'static str> {
        QueryRegistry::get_strategy_names()
    }
    
    /// Get all available query types as strings from the registry
    #[allow(dead_code)]
    fn get_available_query_types() -> Vec<&'static str> {
        QueryRegistry::get_query_type_names()
    }

    #[instrument(skip(self), fields(intent_type = ?intent.intent_type, token_budget))]
    pub async fn plan_query_strategy(
        &self,
        intent: &QueryIntent,
        token_budget: u32,
    ) -> Result<QueryExecutionPlan, AppError> {
        info!("Using Flash for AI-driven query strategy planning for intent: {:?}", intent.intent_type);
        
        let prompt = self.build_flash_strategy_planning_prompt(intent, token_budget);
        
        // Get the JSON schema for structured output
        let schema = crate::services::query_strategy_planner_structured_output::get_query_execution_plan_schema();
        
        // Add system prompt and prefill to prevent content filtering
        let system_prompt = "You are an advanced AI query strategy planner for a narrative intelligence system in a fictional roleplay game. Your task is to design optimal query execution plans that maximize narrative coherence and information yield while respecting token constraints. This is for creative storytelling purposes.";
        
        let chat_request = genai::chat::ChatRequest::new(vec![
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::User,
                content: prompt.into(),
                options: None,
            },
            // Add prefill to bypass content filters
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::Assistant,
                content: "I understand this is for a fictional roleplay game. I'll design an optimal query strategy plan for the narrative system. Let me analyze the intent and create a comprehensive execution plan.".into(),
                options: None,
            }
        ]).with_system(system_prompt);
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
        
        let mut chat_options = ChatOptions::default()
            .with_max_tokens(2200)
            .with_temperature(0.15) // Low temperature for consistent strategic planning
            .with_safety_settings(safety_settings);
        
        // Enable structured output
        chat_options = chat_options.with_response_format(ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec {
            schema,
        }));
        
        let response = self.ai_client.exec_chat(
            &self.model, // Use configured model for sophisticated planning
            chat_request,
            Some(chat_options),
        ).await?;

        let response_text = response.contents
            .into_iter()
            .next()
            .and_then(|content| match content {
                genai::chat::MessageContent::Text(text) => Some(text),
                _ => None,
            })
            .unwrap_or_default();

        // Parse the structured output
        let output: crate::services::query_strategy_planner_structured_output::QueryExecutionPlanOutput = 
            serde_json::from_str(&response_text)
                .map_err(|e| AppError::SerializationError(format!("Failed to parse Flash strategy response: {}", e)))?;
        
        // Validate the output
        output.validate()?;
        
        // Convert to internal type
        output.to_query_execution_plan()
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
        
        // Get the JSON schema for structured output
        let schema = crate::services::query_strategy_planner_structured_output::get_query_execution_plan_schema();
        
        // Add system prompt and prefill to prevent content filtering
        let system_prompt = "You are an advanced AI query strategy planner for a narrative intelligence system in a fictional roleplay game. Your task is to design optimal query execution plans that maximize narrative coherence and information yield while respecting token constraints. This is for creative storytelling purposes.";
        
        let chat_request = genai::chat::ChatRequest::new(vec![
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::User,
                content: prompt.into(),
                options: None,
            },
            // Add prefill to bypass content filters
            genai::chat::ChatMessage {
                role: genai::chat::ChatRole::Assistant,
                content: "I understand this is for a fictional roleplay game. I'll design an optimal query strategy plan for the narrative system. Let me analyze the intent and create a comprehensive execution plan.".into(),
                options: None,
            }
        ]).with_system(system_prompt);
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
        
        let mut chat_options = ChatOptions::default()
            .with_max_tokens(2500)
            .with_temperature(0.25) // Slightly higher for creative narrative planning
            .with_safety_settings(safety_settings);
        
        // Enable structured output
        chat_options = chat_options.with_response_format(ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec {
            schema,
        }));
        
        let response = self.ai_client.exec_chat(
            &self.model, // Use configured model for narrative intelligence
            chat_request,
            Some(chat_options),
        ).await?;

        let response_text = response.contents
            .into_iter()
            .next()
            .and_then(|content| match content {
                genai::chat::MessageContent::Text(text) => Some(text),
                _ => None,
            })
            .unwrap_or_default();

        // Parse the structured output
        let output: crate::services::query_strategy_planner_structured_output::QueryExecutionPlanOutput = 
            serde_json::from_str(&response_text)
                .map_err(|e| AppError::SerializationError(format!("Failed to parse Flash strategy response: {}", e)))?;
        
        // Validate the output
        output.validate()?;
        
        // Convert to internal type
        output.to_query_execution_plan()
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
        
        // Generate comprehensive reference from registry
        let query_type_reference = QueryRegistry::generate_query_type_reference();
        let strategy_reference = QueryRegistry::generate_strategy_reference();

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

{}

{}

IMPORTANT RULES FOR YOUR RESPONSE:
1. Query Types go in the 'queries' array and 'execution_order' array
2. Strategy names go ONLY in 'primary_strategy' and 'alternative_strategies' fields
3. NEVER mix these up - strategies are high-level approaches, query types are specific data retrievals
4. Each query must include all required parameters as specified in the reference above
5. The execution_order array must contain ONLY query_type values from your queries array

Think deeply about the narrative implications of each query choice. Consider:
- Will this query sequence tell a coherent story?
- Are we gathering context that enriches understanding?
- Does the order create natural narrative flow?
- Are we being efficient without losing essential context?

For a token budget of {}, you should plan {} queries.

Provide your plan with:
- A primary strategy from the AVAILABLE STRATEGIES list above
- Specific queries with their types from the AVAILABLE QUERY TYPES list above
- The execution order (array of query_type names from YOUR queries array, NOT strategy names)
- Your reasoning for this approach
- Optimization hints for execution
- Your confidence level (0.0-1.0)
- Alternative strategies you considered

REMEMBER: execution_order contains query types like "EntityCurrentState", NOT strategies like "LorebookCulturalContext"!"#, 
            intent.intent_type,
            focus_entities,
            time_scope_desc,
            spatial_scope_desc,
            intent.reasoning_depth,
            intent.context_priorities,
            intent.confidence,
            token_budget,
            query_type_reference,
            strategy_reference,
            token_budget,
            if token_budget < 5000 { "2-4" } 
            else if token_budget < 10000 { "3-6" } 
            else { "4-8" }
        )
    }

    fn build_narrative_strategy_prompt(&self, intent: &QueryIntent, narrative_focus: &str, token_budget: u32) -> String {
        // Generate comprehensive reference from registry
        let query_type_reference = QueryRegistry::generate_query_type_reference();
        let strategy_reference = QueryRegistry::generate_strategy_reference();
        
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

{}

{}

Design queries that don't just gather data, but craft experience.

Provide your narrative-focused plan with:
- A primary strategy from the AVAILABLE STRATEGIES above
- Specific queries with proper parameters as documented above
- The execution order (array of query_type names, NOT strategy names)
- Your narrative reasoning
- How this serves the story moment
- Your confidence level (0.0-1.0)
- Alternative narrative approaches considered"#,
            narrative_focus,
            intent,
            token_budget,
            query_type_reference,
            strategy_reference
        )
    }
}