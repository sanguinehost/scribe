use std::sync::Arc;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json::Value as JsonValue;
use tracing::{info, instrument, debug, warn};

use crate::{
    llm::AiClient,
    errors::AppError,
    services::{
        context_assembly_engine::AssembledContext,
        query_strategy_planner::QueryStrategy,
    },
};

use crate::services::context_optimization_structured_output::{ContextOptimizationOutput, get_context_optimization_schema};

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
    model: String,
}

impl ContextOptimizationService {
    pub fn new(ai_client: Arc<dyn AiClient>, model: String) -> Self {
        Self { ai_client, model }
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
        let json_schema_spec = genai::chat::JsonSchemaSpec::new(get_context_optimization_schema());
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(4000) // Significantly increased for complex structured output
            .with_temperature(0.2) // Low temperature for consistent optimization
            .with_response_format(genai::chat::ChatResponseFormat::JsonSchemaSpec(json_schema_spec));

        let response = self.ai_client.exec_chat(
            &self.model, // Use configured model for intelligent optimization
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

        if response_text.is_empty() {
            warn!("Empty response from AI for context optimization");
            // Return a default optimization instead of failing
            return Ok(ContextOptimization {
                total_estimated_tokens: context.total_tokens_used,
                optimized_entities: vec![],
                pruned_content: vec![],
                optimization_strategy: OptimizationStrategy::EntityPrioritization,
                confidence: 0.5,
                optimization_reasoning: "AI returned empty response - using unoptimized context".to_string(),
                suggested_refinements: vec![],
            });
        }

        self.parse_structured_optimization_response(&response_text)
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
        let json_schema_spec = genai::chat::JsonSchemaSpec::new(get_context_optimization_schema());
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(4500) // Significantly increased for complex narrative structured output
            .with_temperature(0.3) // Slightly higher for narrative creativity
            .with_response_format(genai::chat::ChatResponseFormat::JsonSchemaSpec(json_schema_spec));

        let response = self.ai_client.exec_chat(
            &self.model, // Use configured model for narrative optimization
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

        if response_text.is_empty() {
            warn!("Empty response from AI for narrative context optimization");
            // Return a default optimization instead of failing
            return Ok(ContextOptimization {
                total_estimated_tokens: context.total_tokens_used,
                optimized_entities: vec![],
                pruned_content: vec![],
                optimization_strategy: OptimizationStrategy::NarrativeCoherence,
                confidence: 0.5,
                optimization_reasoning: "AI returned empty response - using unoptimized context".to_string(),
                suggested_refinements: vec![],
            });
        }

        self.parse_structured_optimization_response(&response_text)
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

PROVIDE YOUR OPTIMIZATION ANALYSIS IN VALID JSON FORMAT:
You must return a JSON object with these fields:
- optimization_reasoning: Clear, concise explanation of your approach (2-3 sentences max)
- optimization_strategy: One of the exact strategy names listed below
- total_estimated_tokens: Number after optimization
- optimized_entities: Array of entities to keep (limit to 3-5 most important)
- pruned_content: Array of content to remove (limit to 3-5 items)
- suggested_refinements: Array of 1-2 improvement suggestions
- confidence: Number between 0.0 and 1.0

KEEP DESCRIPTIONS CONCISE - aim for 1-2 sentences per explanation to avoid truncation.

OPTIMIZATION STRATEGIES (use exact names):
EntityPrioritization, TemporalFiltering, RelevanceClustering, CausalPathFocus, SpatialContextPrioritization, TokenBudgetConstraint, ConservativePruning, AdaptiveOptimization, NarrativeCoherence, EmotionalResonance, ActionPotential

Focus on the most critical elements. Be selective and concise."#,
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

PROVIDE YOUR NARRATIVE OPTIMIZATION ANALYSIS:
- Optimization reasoning: detailed narrative analysis and optimization rationale
- Optimization strategy: strategy that best serves the narrative
- Total estimated tokens after optimization
- Optimized entities: entities to keep with priority scores (0.0-1.0), narrative inclusion reasons, token contributions, and narrative relevance
- Pruned content: content to remove with narrative reasoning and confidence scores
- Suggested refinements: how to better serve the narrative and additional optimization opportunities
- Confidence: your overall confidence level (0.0-1.0)

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

    /// Parse structured AI optimization response
    fn parse_structured_optimization_response(
        &self,
        response: &str,
    ) -> Result<ContextOptimization, AppError> {
        let cleaned = response.trim();
        
        // Try to parse as structured output
        match serde_json::from_str::<ContextOptimizationOutput>(cleaned) {
            Ok(output) => {
                // Validate the structured output
                output.validate()?;
                // Convert to internal type
                output.to_context_optimization()
            }
            Err(e) => {
                warn!("Failed to parse structured optimization response: {}", e);
                warn!("Response content length: {} chars", cleaned.len());
                warn!("Response content (first 1000 chars): {}", &cleaned[..cleaned.len().min(1000)]);
                
                // Check if this looks like a truncation issue
                if cleaned.contains("EOF while parsing") || e.to_string().contains("EOF") {
                    warn!("Response appears to be truncated (EOF error) - may need higher token limits");
                }
                
                // Return a fallback optimization instead of failing
                Ok(ContextOptimization {
                    total_estimated_tokens: 1000, // Conservative estimate
                    optimized_entities: vec![],
                    pruned_content: vec![],
                    optimization_strategy: OptimizationStrategy::ConservativePruning,
                    confidence: 0.2, // Lower confidence due to parsing failure
                    optimization_reasoning: format!("Failed to parse AI optimization response ({}), using conservative fallback. Response may be truncated - consider increasing token limits.", e),
                    suggested_refinements: vec!["Retry optimization with simpler context".to_string(), "Consider increasing max_tokens for structured output".to_string()],
                })
            }
        }
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