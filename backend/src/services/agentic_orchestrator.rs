use std::sync::Arc;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use tracing::{info, debug, warn, instrument};

use crate::{
    errors::AppError,
    PgPool,
    services::{
        intent_detection_service::{IntentDetectionService, QueryIntent},
        query_strategy_planner::{QueryStrategyPlanner, QueryExecutionPlan},
        context_assembly_engine::{ContextAssemblyEngine, AssembledContext},
        context_optimization_service::{ContextOptimizationService, ContextOptimization},
        hybrid_query_service::HybridQueryService,
    },
    llm::AiClient,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticRequest {
    pub user_query: String,
    pub conversation_context: Option<String>,
    pub user_id: Uuid,
    pub chronicle_id: Option<Uuid>,
    pub token_budget: u32,
    pub quality_mode: QualityMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QualityMode {
    Fast,      // Minimal processing for speed
    Balanced,  // Default quality/speed balance
    Thorough,  // Maximum quality analysis
}

impl Default for QualityMode {
    fn default() -> Self {
        Self::Balanced
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticResponse {
    pub optimized_context: String,
    pub execution_summary: ExecutionSummary,
    pub token_usage: TokenUsageSummary,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSummary {
    pub intent_detected: String,
    pub strategy_used: String,
    pub queries_executed: u32,
    pub entities_analyzed: u32,
    pub content_pruned: u32,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageSummary {
    pub intent_detection_tokens: u32,
    pub strategy_planning_tokens: u32,
    pub optimization_tokens: u32,
    pub total_llm_tokens: u32,
    pub context_tokens_generated: u32,
    pub final_tokens_used: u32,
}

pub struct AgenticOrchestrator {
    intent_service: Arc<IntentDetectionService>,
    strategy_planner: Arc<QueryStrategyPlanner>,
    context_engine: Arc<ContextAssemblyEngine>,
    optimization_service: Arc<ContextOptimizationService>,
    ai_client: Arc<dyn AiClient>,
    db_pool: Arc<PgPool>,
}

impl AgenticOrchestrator {
    pub fn new(
        ai_client: Arc<dyn AiClient>,
        hybrid_query_service: Arc<HybridQueryService>,
        db_pool: Arc<PgPool>,
    ) -> Self {
        let intent_service = Arc::new(IntentDetectionService::new(ai_client.clone()));
        let strategy_planner = Arc::new(QueryStrategyPlanner::new(ai_client.clone()));
        let context_engine = Arc::new(ContextAssemblyEngine::new(
            hybrid_query_service,
            db_pool.clone(),
        ));
        let optimization_service = Arc::new(ContextOptimizationService::new(ai_client.clone()));

        Self {
            intent_service,
            strategy_planner,
            context_engine,
            optimization_service,
            ai_client,
            db_pool,
        }
    }

    #[instrument(skip(self), fields(
        user_id = %request.user_id,
        query_len = request.user_query.len(),
        token_budget = request.token_budget,
        quality_mode = ?request.quality_mode
    ))]
    pub async fn process_query(&self, request: AgenticRequest) -> Result<AgenticResponse, AppError> {
        let start_time = std::time::Instant::now();
        let mut token_usage = TokenUsageSummary {
            intent_detection_tokens: 0,
            strategy_planning_tokens: 0,
            optimization_tokens: 0,
            total_llm_tokens: 0,
            context_tokens_generated: 0,
            final_tokens_used: 0,
        };

        info!("Starting agentic query processing for user: {}", request.user_id);

        // Phase 1: Intent Detection
        debug!("Phase 1: Detecting intent for query");
        let intent = self.intent_service.detect_intent(
            &request.user_query,
            request.conversation_context.as_deref(),
        ).await?;

        // Estimate token usage for intent detection (Flash-Lite: ~100-200 tokens)
        token_usage.intent_detection_tokens = 150;
        token_usage.total_llm_tokens += token_usage.intent_detection_tokens;

        info!("Intent detected: {:?} with confidence: {:.2}", intent.intent_type, intent.confidence);

        // Phase 2: Strategy Planning
        debug!("Phase 2: Planning query strategy");
        let strategy_plan = self.strategy_planner.plan_query_strategy(
            &intent,
            request.token_budget,
        ).await?;

        // Estimate token usage for strategy planning (Flash-Lite: ~200-400 tokens)
        token_usage.strategy_planning_tokens = 300;
        token_usage.total_llm_tokens += token_usage.strategy_planning_tokens;

        info!("Strategy planned: {:?} with {} queries", 
              strategy_plan.primary_strategy, strategy_plan.queries.len());

        // Phase 3: Context Assembly
        debug!("Phase 3: Assembling context from planned queries");
        let assembled_context = self.context_engine.execute_plan(&strategy_plan, request.user_id).await?;

        token_usage.context_tokens_generated = assembled_context.total_tokens_used;
        info!("Context assembled: {} tokens from {} queries", 
              assembled_context.total_tokens_used, assembled_context.results.len());

        // Phase 4: Context Optimization
        debug!("Phase 4: Optimizing context for token budget");
        let optimization = self.optimization_service.optimize_context(
            &assembled_context,
            request.token_budget,
            &request.user_query,
        ).await?;

        // Estimate token usage for optimization (Flash-Lite: ~300-500 tokens)
        token_usage.optimization_tokens = 400;
        token_usage.total_llm_tokens += token_usage.optimization_tokens;

        token_usage.final_tokens_used = optimization.total_estimated_tokens;

        info!("Context optimized: {} entities, {} pruned items, final tokens: {}", 
              optimization.optimized_entities.len(), 
              optimization.pruned_content.len(),
              optimization.total_estimated_tokens);

        // Phase 5: Generate Final Context String
        debug!("Phase 5: Generating final context string");
        let optimized_context = self.build_final_context_string(&optimization, &assembled_context)?;

        let execution_time = start_time.elapsed().as_millis() as u64;

        // Build execution summary
        let execution_summary = ExecutionSummary {
            intent_detected: format!("{:?}", intent.intent_type),
            strategy_used: format!("{:?}", strategy_plan.primary_strategy),
            queries_executed: assembled_context.results.len() as u32,
            entities_analyzed: optimization.optimized_entities.len() as u32,
            content_pruned: optimization.pruned_content.len() as u32,
            execution_time_ms: execution_time,
        };

        let response = AgenticResponse {
            optimized_context,
            execution_summary,
            token_usage,
            confidence: intent.confidence.min(optimization.confidence),
        };

        info!(
            "Agentic processing completed in {}ms, final confidence: {:.2}",
            execution_time,
            response.confidence
        );

        Ok(response)
    }

    fn build_final_context_string(
        &self,
        optimization: &ContextOptimization,
        assembled_context: &AssembledContext,
    ) -> Result<String, AppError> {
        let mut context_parts = Vec::new();

        // Add optimization summary
        context_parts.push(format!(
            "<!-- Context optimized using {} strategy with {:.1}% confidence -->",
            format!("{:?}", optimization.optimization_strategy),
            optimization.confidence * 100.0
        ));

        // Add entity information
        if !optimization.optimized_entities.is_empty() {
            context_parts.push("\n# Relevant Entities".to_string());
            for entity in &optimization.optimized_entities {
                context_parts.push(format!(
                    "- **{}** (priority: {:.2}, tokens: {}): {}",
                    entity.name,
                    entity.priority_score,
                    entity.token_contribution,
                    entity.inclusion_reason
                ));
            }
        }

        // Add query results (simplified for now - would be enhanced with actual data)
        if !assembled_context.results.is_empty() {
            context_parts.push("\n# Context Data".to_string());
            for (i, result) in assembled_context.results.iter().enumerate() {
                let result_summary = match result {
                    crate::services::context_assembly_engine::QueryExecutionResult::EntityEvents(r) => {
                        format!("Entity Events: {} entities in scope '{}'", r.entities.len(), r.time_scope)
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::SpatialEntities(r) => {
                        format!("Spatial Context: {} entities at '{}'", r.entities.len(), r.location_name)
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::EntityRelationships(r) => {
                        format!("Relationships: {} connections for entities [{}]", 
                               r.relationships.len(), r.entity_names.join(", "))
                    },
                    crate::services::context_assembly_engine::QueryExecutionResult::CausalChain(r) => {
                        format!("Causal Analysis: {} causal links from '{}'", 
                               r.causal_chain.len(), r.from_entity)
                    },
                    _ => format!("Query Result {}: Various data points", i + 1),
                };
                context_parts.push(format!("## {}", result_summary));
            }
        }

        // Add pruning information if content was removed
        if !optimization.pruned_content.is_empty() {
            context_parts.push("\n<!-- Content Pruned for Token Efficiency -->".to_string());
            for pruned in &optimization.pruned_content {
                context_parts.push(format!(
                    "<!-- Pruned {}: {} ({} tokens saved) -->",
                    pruned.content_type,
                    pruned.reason,
                    pruned.tokens_saved
                ));
            }
        }

        let final_context = context_parts.join("\n");
        Ok(final_context)
    }

    // Quick method for integration testing
    pub async fn process_simple_query(
        &self,
        query: &str,
        user_id: Uuid,
    ) -> Result<String, AppError> {
        let request = AgenticRequest {
            user_query: query.to_string(),
            conversation_context: None,
            user_id,
            chronicle_id: None,
            token_budget: 4000,
            quality_mode: QualityMode::default(),
        };

        let response = self.process_query(request).await?;
        Ok(response.optimized_context)
    }
}