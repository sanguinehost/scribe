use std::sync::Arc;
use serde::{Serialize, Deserialize};
use tracing::{info, instrument};

use crate::{
    llm::AiClient,
    errors::AppError,
    services::{
        context_assembly_engine::AssembledContext,
        query_strategy_planner::QueryStrategy,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextOptimization {
    pub total_estimated_tokens: u32,
    pub optimized_entities: Vec<OptimizedEntity>,
    pub pruned_content: Vec<PrunedContent>,
    pub optimization_strategy: OptimizationStrategy,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizedEntity {
    pub entity_id: String,
    pub name: String,
    pub priority_score: f32,
    pub inclusion_reason: String,
    pub token_contribution: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrunedContent {
    pub content_type: String,
    pub entity_name: String,
    pub reason: String,
    pub tokens_saved: u32,
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
}

pub struct ContextOptimizationService {
    ai_client: Arc<dyn AiClient>,
}

impl ContextOptimizationService {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self { ai_client }
    }

    #[instrument(skip(self), fields(
        strategy = ?context.strategy_used,
        total_tokens = context.total_tokens_used,
        token_budget,
        query_len = user_query.len()
    ))]
    pub async fn optimize_context(
        &self,
        context: &AssembledContext,
        token_budget: u32,
        user_query: &str,
    ) -> Result<ContextOptimization, AppError> {
        let prompt = self.build_optimization_prompt(context, token_budget, user_query);
        
        info!("Optimizing context with {} results for token budget: {}", 
              context.results.len(), token_budget);
        
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(2000)
            .with_temperature(0.2); // Low temperature for consistent optimization decisions
        
        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash-lite-preview-06-17", // Use Flash-Lite for cost-effective optimization
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

        self.parse_optimization_response(&response_text)
    }

    fn build_optimization_prompt(
        &self,
        context: &AssembledContext,
        token_budget: u32,
        user_query: &str,
    ) -> String {
        let strategy_desc = match context.strategy_used {
            QueryStrategy::CausalChainTraversal => "Causal analysis focused on cause-effect relationships",
            QueryStrategy::SpatialContextMapping => "Spatial analysis of locations and entities",
            QueryStrategy::RelationshipNetworkTraversal => "Relationship analysis between entities",
            QueryStrategy::TemporalStateReconstruction => "Temporal analysis of state changes over time",
            QueryStrategy::CausalProjection => "Predictive analysis based on causal factors",
            QueryStrategy::NarrativeContextAssembly => "Narrative context for story continuation",
            QueryStrategy::StateSnapshot => "Current state inquiry of entities",
            QueryStrategy::ComparativeAnalysis => "Comparative analysis between entities",
        };

        let current_context_summary = context.results.iter()
            .map(|result| {
                match result {
                    crate::services::context_assembly_engine::QueryExecutionResult::EntityEvents(r) => {
                        format!("EntityEvents for {} entities ({})", r.entities.len(), r.time_scope)
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::SpatialEntities(r) => {
                        format!("SpatialEntities at {} ({} entities)", r.location_name, r.entities.len())
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::EntityRelationships(r) => {
                        format!("EntityRelationships for {} ({} relationships)", 
                               r.entity_names.join(", "), r.relationships.len())
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::CausalChain(r) => {
                        format!("CausalChain from {} ({} links)", r.from_entity, r.causal_chain.len())
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::TimelineEvents(r) => {
                        format!("TimelineEvents for {} ({} events)", 
                               r.entity_names.join(", "), r.timeline.len())
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::EntityCurrentState(r) => {
                        format!("EntityCurrentState for {} ({} states)", 
                               r.entity_names.join(", "), r.current_states.len())
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::EntityStates(r) => {
                        format!("EntityStates in scope '{}' ({} entities)", r.scope, r.entities.len())
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::SharedEvents(r) => {
                        format!("SharedEvents for {} ({} events)", 
                               r.entity_names.join(", "), r.shared_events.len())
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::CausalFactors(r) => {
                        format!("CausalFactors for {} in {} ({} factors)", 
                               r.entity, r.scenario, r.factors.len())
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::StateTransitions(r) => {
                        format!("StateTransitions for {} ({} transitions)", 
                               r.entity, r.transitions.len())
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::RecentEvents(r) => {
                        format!("RecentEvents in {} ({} events)", r.time_scope, r.events.len())
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::HistoricalParallels(r) => {
                        format!("HistoricalParallels for {} ({} parallels)", 
                               r.scenario_type, r.parallels.len())
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::ActiveEntities(r) => {
                        format!("ActiveEntities ({} entities, threshold: {})", 
                               r.entities.len(), r.activity_threshold)
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::NarrativeThreads(r) => {
                        format!("NarrativeThreads ({} threads, status: {})", 
                               r.threads.len(), r.status)
                    },
                }
            })
            .collect::<Vec<_>>()
            .join(", ");

        format!(r#"You are a context optimization expert for an ECS-based narrative AI system. Your job is to intelligently filter and prioritize context to fit within token budgets while maximizing relevance.

OPTIMIZATION TASK:
- User Query: "{}"
- Strategy Used: {} 
- Current Context: {}
- Current Token Usage: {} tokens
- Target Token Budget: {} tokens
- Success Rate: {:.1}%

OPTIMIZATION STRATEGIES:
1. EntityPrioritization: Focus on most relevant entities, remove peripheral ones
2. TemporalFiltering: Filter by time relevance, remove outdated information
3. RelevanceClustering: Group related entities, remove weak connections
4. CausalPathFocus: Keep only entities in direct causal chains
5. SpatialContextPrioritization: Focus on spatially relevant entities
6. TokenBudgetConstraint: Aggressive pruning to meet strict budgets
7. ConservativePruning: Minimal pruning when confidence is low
8. AdaptiveOptimization: Combine multiple strategies intelligently

OPTIMIZATION PRINCIPLES:
- Never remove entities directly mentioned in the user query
- Prioritize entities with higher relevance scores
- Consider query intent and strategy when filtering
- Balance completeness vs token efficiency
- Provide clear reasoning for all optimization decisions

TOKEN ESTIMATION GUIDELINES:
- EntityEvents: ~200-400 tokens per entity
- EntityRelationships: ~150-300 tokens per relationship  
- CausalChain: ~300-500 tokens per causal link
- SpatialEntities: ~100-250 tokens per entity
- TimelineEvents: ~250-400 tokens per event
- State information: ~100-200 tokens per entity

Respond with a JSON object:
{{
    "total_estimated_tokens": <estimated_tokens_after_optimization>,
    "optimized_entities": [
        {{
            "entity_id": "<unique_id>",
            "name": "<entity_name>",
            "priority_score": 0.0-1.0,
            "inclusion_reason": "<why_included>",
            "token_contribution": <estimated_tokens>
        }}
    ],
    "pruned_content": [
        {{
            "content_type": "<EntityEvents|SpatialEntities|etc>",
            "entity_name": "<entity_or_scope>",
            "reason": "<why_pruned>",
            "tokens_saved": <estimated_tokens_saved>
        }}
    ],
    "optimization_strategy": "<primary_strategy_used>",
    "confidence": 0.0-1.0
}}

EXAMPLES:
- For causal queries: Focus on EntityPrioritization + CausalPathFocus
- For spatial queries: Use SpatialContextPrioritization + RelevanceClustering
- For tight budgets: Apply TokenBudgetConstraint with aggressive pruning
- For unclear queries: Use ConservativePruning to avoid losing important context

Optimize the context to best serve the user query within the token budget:
"#, 
            user_query,
            strategy_desc,
            current_context_summary,
            context.total_tokens_used,
            token_budget,
            context.success_rate * 100.0
        )
    }

    fn parse_optimization_response(&self, response: &str) -> Result<ContextOptimization, AppError> {
        let cleaned = response.trim();
        
        let json_value: serde_json::Value = serde_json::from_str(cleaned)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse optimization response JSON: {}", e)))?;
        
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
            _ => return Err(AppError::SerializationError("Invalid optimization_strategy".to_string())),
        };

        // Parse optimized entities
        let optimized_entities = json_value["optimized_entities"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|entity_value| {
                Some(OptimizedEntity {
                    entity_id: entity_value.get("entity_id")?.as_str()?.to_string(),
                    name: entity_value.get("name")?.as_str()?.to_string(),
                    priority_score: entity_value.get("priority_score")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.5) as f32,
                    inclusion_reason: entity_value.get("inclusion_reason")?.as_str()?.to_string(),
                    token_contribution: entity_value.get("token_contribution")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                })
            })
            .collect();

        // Parse pruned content
        let pruned_content = json_value["pruned_content"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|pruned_value| {
                Some(PrunedContent {
                    content_type: pruned_value.get("content_type")?.as_str()?.to_string(),
                    entity_name: pruned_value.get("entity_name")?.as_str()?.to_string(),
                    reason: pruned_value.get("reason")?.as_str()?.to_string(),
                    tokens_saved: pruned_value.get("tokens_saved")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                })
            })
            .collect();

        Ok(ContextOptimization {
            total_estimated_tokens: json_value["total_estimated_tokens"]
                .as_u64()
                .unwrap_or(0) as u32,
            optimized_entities,
            pruned_content,
            optimization_strategy,
            confidence: json_value["confidence"]
                .as_f64()
                .unwrap_or(0.5) as f32,
        })
    }
}