use std::sync::Arc;
use serde::{Serialize, Deserialize};
use serde_json::Value as JsonValue;
use tracing::{info, instrument, debug};

use crate::{
    llm::AiClient,
    errors::AppError,
    services::{
        context_assembly_engine::AssembledContext,
        query_strategy_planner::QueryStrategy,
    },
};

/// AI-optimized context structure representing intelligent pruning decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextOptimization {
    pub total_estimated_tokens: u32,
    pub optimized_entities: Vec<OptimizedEntity>,
    pub pruned_content: Vec<PrunedContent>,
    pub optimization_strategy: OptimizationStrategy,
    pub confidence: f32,
    /// AI-generated reasoning for the optimization approach
    pub optimization_reasoning: String,
    /// AI-suggested follow-up optimizations
    pub suggested_refinements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedEntity {
    pub entity_id: String,
    pub name: String,
    pub priority_score: f32,
    pub inclusion_reason: String,
    pub token_contribution: u32,
    /// AI-determined relevance to current narrative context
    pub narrative_relevance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrunedContent {
    pub content_type: String,
    pub entity_name: String,
    pub reason: String,
    pub tokens_saved: u32,
    /// AI confidence in this pruning decision
    pub pruning_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OptimizationStrategy {
    EntityPrioritization,
    TemporalFiltering,
    RelevanceClustering,
    CausalPathFocus,
    SpatialContextPrioritization,
    TokenBudgetConstraint,
    ConservativePruning,
    AdaptiveOptimization,
    /// New AI-driven strategies
    NarrativeCoherence,
    EmotionalResonance,
    ActionPotential,
}

pub struct ContextOptimizationService {
    ai_client: Arc<dyn AiClient>,
}

impl ContextOptimizationService {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self { ai_client }
    }

    #[instrument(skip(self, context, strategy), fields(context_results = context.results.len()))]
    pub async fn optimize_context(
        &self,
        context: &AssembledContext,
        strategy: Option<&QueryStrategy>,
        token_budget: Option<u32>,
    ) -> Result<ContextOptimization, AppError> {
        info!(
            "Using Flash-Lite for AI-driven context optimization with {} results",
            context.results.len()
        );

        let prompt = self.build_flash_optimization_prompt(context, strategy, token_budget);

        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1500)
            .with_temperature(0.2); // Low temperature for consistent optimization

        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-lite-preview-06-17", // Flash-Lite for intelligent optimization
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

        self.parse_flash_optimization_response(&response_text, context)
    }

    /// AI-powered optimization with narrative-aware approach
    #[instrument(skip(self, context), fields(narrative_focus))]
    pub async fn optimize_for_narrative(
        &self,
        context: &AssembledContext,
        narrative_focus: &str,
        token_budget: Option<u32>,
    ) -> Result<ContextOptimization, AppError> {
        info!(
            "Using Flash for narrative-focused AI context optimization: {}",
            narrative_focus
        );

        let prompt = self.build_narrative_optimization_prompt(context, narrative_focus, token_budget);

        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1800)
            .with_temperature(0.3); // Slightly higher for narrative creativity

        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-preview-06-17", // Full Flash for narrative optimization
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

        self.parse_narrative_optimization_response(&response_text, context)
    }

    /// Build AI prompt for intelligent context optimization
    fn build_flash_optimization_prompt(
        &self,
        context: &AssembledContext,
        strategy: Option<&QueryStrategy>,
        token_budget: Option<u32>,
    ) -> String {
        let strategy_info = if let Some(s) = strategy {
            format!("Query Strategy: {:?}", s)
        } else {
            format!("Strategy Used: {:?}", context.strategy_used)
        };

        let budget_info = token_budget.map_or(
            "No specific token budget constraint".to_string(),
            |b| format!("Target token budget: {} tokens", b)
        );

        // Serialize the query results for AI analysis
        let results_json = serde_json::to_string_pretty(&context.results)
            .unwrap_or_else(|_| "[]".to_string());

        format!(r#"You are an intelligent context optimization system for a narrative AI framework. Your task is to optimize assembled context for token efficiency while preserving narrative coherence and essential information.

ASSEMBLED CONTEXT:
Total Results: {}
Execution Time: {}ms
Success Rate: {}%
Current Token Usage: {}

Query Results:
{}

{}
{}

OPTIMIZATION TASK:
Analyze this assembled context from multiple query results and determine the optimal subset that maintains narrative coherence while respecting token constraints. Consider:
1. Entity narrative importance across all results
2. Relationship criticality for understanding
3. Event temporal relevance and causal significance
4. Information density vs redundancy across different result types
5. Narrative flow requirements

RESPOND WITH JSON:
{{
    "optimization_reasoning": "<comprehensive explanation of optimization approach>",
    "optimization_strategy": "<one of: EntityPrioritization, TemporalFiltering, RelevanceClustering, CausalPathFocus, SpatialContextPrioritization, TokenBudgetConstraint, ConservativePruning, AdaptiveOptimization, NarrativeCoherence, EmotionalResonance, ActionPotential>",
    "total_estimated_tokens": <number>,
    "optimized_entities": [
        {{
            "entity_id": "<id>",
            "name": "<entity_name>",
            "priority_score": <0.0-1.0>,
            "inclusion_reason": "<why this entity is essential>",
            "token_contribution": <estimated_tokens>,
            "narrative_relevance": <0.0-1.0>
        }}
    ],
    "pruned_content": [
        {{
            "content_type": "<entity|relationship|event|result_type>",
            "entity_name": "<name_of_pruned_content>",
            "reason": "<why this was pruned>",
            "tokens_saved": <number>,
            "pruning_confidence": <0.0-1.0>
        }}
    ],
    "suggested_refinements": [
        "<potential optimization improvement 1>",
        "<potential optimization improvement 2>"
    ],
    "confidence": <0.0-1.0>
}}

OPTIMIZATION STRATEGIES:
- EntityPrioritization: Focus on most important entities
- TemporalFiltering: Prioritize recent/relevant time periods
- RelevanceClustering: Group related information
- CausalPathFocus: Emphasize cause-effect chains
- SpatialContextPrioritization: Focus on location-relevant content
- TokenBudgetConstraint: Strict adherence to token limits
- ConservativePruning: Minimal removal approach
- AdaptiveOptimization: Balance multiple factors
- NarrativeCoherence: Maintain story flow
- EmotionalResonance: Preserve emotional context
- ActionPotential: Focus on actionable information

Be intelligent about what to keep and what to prune. Preserve narrative-critical information even if it uses more tokens."#,
            context.results.len(),
            context.execution_time_ms,
            context.success_rate,
            context.total_tokens_used,
            results_json,
            strategy_info,
            budget_info
        )
    }

    /// Build AI prompt for narrative-focused optimization
    fn build_narrative_optimization_prompt(
        &self,
        context: &AssembledContext,
        narrative_focus: &str,
        token_budget: Option<u32>,
    ) -> String {
        let budget_info = token_budget.map_or(
            "Optimize for narrative quality over token count".to_string(),
            |b| format!("Target token budget: {} tokens (flexible for narrative needs)", b)
        );

        let entities_summary = self.create_entity_summary(&context.results);
        let relationships_summary = self.create_relationship_summary(&context.results);
        let events_summary = self.create_events_summary(&context.results);

        format!(r#"You are an expert narrative context optimizer for an interactive storytelling system. Your task is to intelligently prune and optimize context while preserving the essence of the narrative moment.

NARRATIVE FOCUS:
"{}"

CURRENT CONTEXT SUMMARY:
Entities: {}
Relationships: {}
Recent Events: {}

{}

NARRATIVE OPTIMIZATION TASK:
Analyze this context through the lens of the narrative focus. Optimize for:
1. **Narrative Coherence**: Keep elements essential to understanding the current scene
2. **Emotional Continuity**: Preserve emotional stakes and character motivations
3. **Action Relevance**: Prioritize information that drives or supports current actions
4. **Atmospheric Integrity**: Maintain world-building elements that enhance immersion
5. **Dramatic Tension**: Keep elements that create or resolve narrative tension

CONSIDER:
- Character arcs and development needs
- Chekhov's gun principle (mentioned elements should be relevant)
- Pacing requirements (too much context slows narrative)
- Reader/player cognitive load
- Foreshadowing and callbacks

RESPOND WITH JSON:
{{
    "optimization_reasoning": "<detailed narrative analysis and optimization rationale>",
    "optimization_strategy": "<strategy that best serves the narrative>",
    "total_estimated_tokens": <number>,
    "optimized_entities": [
        {{
            "entity_id": "<id>",
            "name": "<entity_name>",
            "priority_score": <0.0-1.0>,
            "inclusion_reason": "<narrative reason for inclusion>",
            "token_contribution": <estimated_tokens>,
            "narrative_relevance": <0.0-1.0>
        }}
    ],
    "pruned_content": [
        {{
            "content_type": "<entity|relationship|event>",
            "entity_name": "<name>",
            "reason": "<narrative reason for pruning>",
            "tokens_saved": <number>,
            "pruning_confidence": <0.0-1.0>
        }}
    ],
    "suggested_refinements": [
        "<how to better serve the narrative>",
        "<additional optimization opportunities>"
    ],
    "confidence": <0.0-1.0>
}}

Think like a master storyteller editing a manuscript - keep what serves the story, cut what doesn't."#,
            narrative_focus,
            entities_summary,
            relationships_summary,
            events_summary,
            budget_info
        )
    }

    /// Create concise summary for assembled context results
    fn create_entity_summary(&self, results: &[crate::services::context_assembly_engine::QueryExecutionResult]) -> String {
        let mut entity_count = 0;
        for result in results {
            match result {
                crate::services::context_assembly_engine::QueryExecutionResult::EntityEvents(r) => {
                    entity_count += r.entities.len();
                },
                crate::services::context_assembly_engine::QueryExecutionResult::ActiveEntities(r) => {
                    entity_count += r.entities.len();
                },
                crate::services::context_assembly_engine::QueryExecutionResult::EntityStates(r) => {
                    entity_count += r.entities.len();
                },
                _ => {}
            }
        }
        format!("{} total entities from {} query results", entity_count, results.len())
    }

    /// Create concise relationship summary from results
    fn create_relationship_summary(&self, results: &[crate::services::context_assembly_engine::QueryExecutionResult]) -> String {
        let mut relationship_count = 0;
        for result in results {
            if let crate::services::context_assembly_engine::QueryExecutionResult::EntityRelationships(r) = result {
                relationship_count += r.relationships.len();
            }
        }
        if relationship_count == 0 {
            "No relationships".to_string()
        } else {
            format!("{} total relationships", relationship_count)
        }
    }

    /// Create concise events summary from results
    fn create_events_summary(&self, results: &[crate::services::context_assembly_engine::QueryExecutionResult]) -> String {
        let mut event_count = 0;
        for result in results {
            match result {
                crate::services::context_assembly_engine::QueryExecutionResult::RecentEvents(r) => {
                    event_count += r.events.len();
                },
                crate::services::context_assembly_engine::QueryExecutionResult::TimelineEvents(r) => {
                    event_count += r.timeline.len();
                },
                _ => {}
            }
        }
        if event_count == 0 {
            "No recent events".to_string()
        } else {
            format!("{} total events", event_count)
        }
    }

    /// Parse AI optimization response
    fn parse_flash_optimization_response(
        &self,
        response: &str,
        context: &AssembledContext,
    ) -> Result<ContextOptimization, AppError> {
        let cleaned = response.trim();
        
        let json_value: JsonValue = serde_json::from_str(cleaned)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse Flash optimization response: {}", e)))?;

        // Parse optimization strategy
        let optimization_strategy = match json_value["optimization_strategy"].as_str() {
            Some("EntityPrioritization") => OptimizationStrategy::EntityPrioritization,
            Some("TemporalFiltering") => OptimizationStrategy::TemporalFiltering,
            Some("RelevanceClustering") => OptimizationStrategy::RelevanceClustering,
            Some("CausalPathFocus") => OptimizationStrategy::CausalPathFocus,
            Some("SpatialContextPrioritization") => OptimizationStrategy::SpatialContextPrioritization,
            Some("TokenBudgetConstraint") => OptimizationStrategy::TokenBudgetConstraint,
            Some("ConservativePruning") => OptimizationStrategy::ConservativePruning,
            Some("AdaptiveOptimization") => OptimizationStrategy::AdaptiveOptimization,
            Some("NarrativeCoherence") => OptimizationStrategy::NarrativeCoherence,
            Some("EmotionalResonance") => OptimizationStrategy::EmotionalResonance,
            Some("ActionPotential") => OptimizationStrategy::ActionPotential,
            _ => OptimizationStrategy::AdaptiveOptimization, // Default fallback
        };

        // Parse optimized entities
        let optimized_entities = json_value["optimized_entities"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|entity| {
                Some(OptimizedEntity {
                    entity_id: entity["entity_id"].as_str()?.to_string(),
                    name: entity["name"].as_str()?.to_string(),
                    priority_score: (entity["priority_score"].as_f64()? as f32).clamp(0.0, 1.0),
                    inclusion_reason: entity["inclusion_reason"].as_str()?.to_string(),
                    token_contribution: entity["token_contribution"].as_u64()? as u32,
                    narrative_relevance: entity["narrative_relevance"]
                        .as_f64()
                        .unwrap_or(0.5)
                        .clamp(0.0, 1.0) as f32,
                })
            })
            .collect();

        // Parse pruned content
        let pruned_content = json_value["pruned_content"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|pruned| {
                Some(PrunedContent {
                    content_type: pruned["content_type"].as_str()?.to_string(),
                    entity_name: pruned["entity_name"].as_str()?.to_string(),
                    reason: pruned["reason"].as_str()?.to_string(),
                    tokens_saved: pruned["tokens_saved"].as_u64()? as u32,
                    pruning_confidence: pruned["pruning_confidence"]
                        .as_f64()
                        .unwrap_or(0.8)
                        .clamp(0.0, 1.0) as f32,
                })
            })
            .collect();

        // Parse suggested refinements
        let suggested_refinements = json_value["suggested_refinements"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        // Extract reasoning
        let optimization_reasoning = json_value["optimization_reasoning"]
            .as_str()
            .unwrap_or("AI optimization applied")
            .to_string();

        Ok(ContextOptimization {
            total_estimated_tokens: json_value["total_estimated_tokens"]
                .as_u64()
                .unwrap_or(1000) as u32,
            optimized_entities,
            pruned_content,
            optimization_strategy,
            confidence: json_value["confidence"]
                .as_f64()
                .unwrap_or(0.85)
                .clamp(0.0, 1.0) as f32,
            optimization_reasoning,
            suggested_refinements,
        })
    }

    /// Parse narrative-focused optimization response
    fn parse_narrative_optimization_response(
        &self,
        response: &str,
        context: &AssembledContext,
    ) -> Result<ContextOptimization, AppError> {
        // Use the same parsing logic as regular optimization
        // The AI will provide narrative-focused reasoning and selections
        self.parse_flash_optimization_response(response, context)
    }

    /// Estimate token count for a piece of content
    pub fn estimate_tokens(&self, content: &str) -> u32 {
        // Rough estimation: ~4 characters per token
        (content.len() as f32 / 4.0).ceil() as u32
    }

    /// Legacy method for compatibility with existing code
    pub async fn optimize_context_legacy(
        &self,
        context: &AssembledContext,
        token_budget: u32,
        user_query: &str,
    ) -> Result<ContextOptimization, AppError> {
        // For legacy compatibility, we'll use the narrative optimization 
        // with the user query as the narrative focus
        self.optimize_for_narrative(context, user_query, Some(token_budget)).await
    }
}