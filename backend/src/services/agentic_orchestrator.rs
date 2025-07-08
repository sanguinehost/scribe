use std::sync::Arc;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use tracing::{info, debug, warn, instrument};
use secrecy::SecretBox;

use crate::{
    errors::AppError,
    PgPool,
    services::{
        intent_detection_service::{IntentDetectionService, QueryIntent},
        query_strategy_planner::{QueryStrategyPlanner, QueryExecutionPlan},
        context_assembly_engine::{ContextAssemblyEngine, AssembledContext},
        context_optimization_service::{ContextOptimizationService, ContextOptimization},
        agentic_state_update_service::{AgenticStateUpdateService, StateUpdateResult},
        hybrid_query_service::HybridQueryService,
        agentic_metrics::{
            AgenticMetricsCollector, MetricsConfig, RequestTracker, AiCallMetric, 
            DbQueryMetric, ErrorInfo, TokenUsageEntry
        },
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
    #[serde(skip)] // Skip serialization for security
    pub user_dek: Option<std::sync::Arc<secrecy::SecretBox<Vec<u8>>>>,
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
    state_update_service: Arc<AgenticStateUpdateService>,
    optimization_service: Arc<ContextOptimizationService>,
    ai_client: Arc<dyn AiClient>,
    db_pool: Arc<PgPool>,
    metrics_collector: Arc<AgenticMetricsCollector>,
}

impl AgenticOrchestrator {
    pub fn new(
        ai_client: Arc<dyn AiClient>,
        hybrid_query_service: Arc<HybridQueryService>,
        db_pool: Arc<PgPool>,
        state_update_service: Arc<AgenticStateUpdateService>,
    ) -> Self {
        let intent_service = Arc::new(IntentDetectionService::new(ai_client.clone()));
        let strategy_planner = Arc::new(QueryStrategyPlanner::new(ai_client.clone()));
        let encryption_service = Arc::new(crate::services::EncryptionService::new());
        let context_engine = Arc::new(ContextAssemblyEngine::new(
            hybrid_query_service,
            db_pool.clone(),
            encryption_service,
            ai_client.clone(),
        ));
        let optimization_service = Arc::new(ContextOptimizationService::new(ai_client.clone()));
        
        // Initialize metrics collector with default config
        let metrics_collector = Arc::new(AgenticMetricsCollector::new(MetricsConfig::default()));

        Self {
            intent_service,
            strategy_planner,
            context_engine,
            state_update_service,
            optimization_service,
            ai_client,
            db_pool,
            metrics_collector,
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

        // Start metrics tracking for this request
        let mut tracker = self.metrics_collector.start_request_tracking(
            request.user_id,
            request.quality_mode.clone(),
            request.token_budget,
        ).await;

        info!("Starting agentic query processing for user: {}", request.user_id);

        // Execute the main processing logic and handle errors for metrics
        let result = self.process_query_internal(&mut tracker, &mut token_usage, &request).await;
        
        match &result {
            Ok(response) => {
                // Record successful completion in metrics
                let _ = self.metrics_collector.record_request_completion(
                    tracker,
                    true, // success
                    Some(response.confidence),
                    None, // no error
                ).await;
            }
            Err(error) => {
                // Record failed completion in metrics
                let error_info = ErrorInfo {
                    error_type: "processing_error".to_string(),
                    error_phase: "unknown".to_string(), // Would need more specific tracking
                    error_message: error.to_string(),
                    recovery_attempted: false,
                    recovery_success: false,
                };
                
                let _ = self.metrics_collector.record_request_completion(
                    tracker,
                    false, // failure
                    None,
                    Some(error_info),
                ).await;
            }
        }

        result
    }

    async fn process_query_internal(
        &self,
        tracker: &mut RequestTracker,
        token_usage: &mut TokenUsageSummary,
        request: &AgenticRequest,
    ) -> Result<AgenticResponse, AppError> {
        let start_time = std::time::Instant::now();

        // Phase 1: Intent Detection
        debug!("Phase 1: Detecting intent for query");
        let phase_timer = tracker.start_phase_timing("intent_detection");
        let intent_start = std::time::Instant::now();
        
        let intent = self.intent_service.detect_intent(
            &request.user_query,
            request.conversation_context.as_deref(),
        ).await?;
        
        let intent_duration = intent_start.elapsed();
        phase_timer.finish(tracker);

        // Record AI call metrics for intent detection
        tracker.record_ai_call(AiCallMetric {
            call_purpose: "intent_detection".to_string(),
            response_time: intent_duration,
            tokens_used: 150, // Estimated tokens
            success: true,
            model: "flash-lite".to_string(),
        });

        // Estimate token usage for intent detection (Flash-Lite: ~100-200 tokens)
        token_usage.intent_detection_tokens = 150;
        token_usage.total_llm_tokens += token_usage.intent_detection_tokens;

        info!("Intent detected: {:?} with confidence: {:.2}", intent.intent_type, intent.confidence);

        // Phase 2: Strategy Planning
        debug!("Phase 2: Planning query strategy");
        let phase_timer = tracker.start_phase_timing("strategy_planning");
        let strategy_start = std::time::Instant::now();
        
        let strategy_plan = self.strategy_planner.plan_query_strategy(
            &intent,
            request.token_budget,
        ).await?;
        
        let strategy_duration = strategy_start.elapsed();
        phase_timer.finish(tracker);

        // Record AI call metrics for strategy planning
        tracker.record_ai_call(AiCallMetric {
            call_purpose: "strategy_planning".to_string(),
            response_time: strategy_duration,
            tokens_used: 300, // Estimated tokens
            success: true,
            model: "flash-lite".to_string(),
        });

        // Estimate token usage for strategy planning (Flash-Lite: ~200-400 tokens)
        token_usage.strategy_planning_tokens = 300;
        token_usage.total_llm_tokens += token_usage.strategy_planning_tokens;

        info!("Strategy planned: {:?} with {} queries", 
              strategy_plan.primary_strategy, strategy_plan.queries.len());

        // Phase 3: Context Assembly
        debug!("Phase 3: Assembling context from planned queries");
        let phase_timer = tracker.start_phase_timing("context_assembly");
        let assembly_start = std::time::Instant::now();
        
        let assembled_context = self.context_engine.execute_plan(&strategy_plan, request.user_id, request.user_dek.as_ref()).await?;
        
        let assembly_duration = assembly_start.elapsed();
        phase_timer.finish(tracker);

        // Record DB query metrics for context assembly (estimated)
        tracker.record_db_query(DbQueryMetric {
            query_type: "context_assembly".to_string(),
            response_time: assembly_duration,
            result_count: assembled_context.results.len(),
            success: true,
        });

        token_usage.context_tokens_generated = assembled_context.total_tokens_used;
        info!("Context assembled: {} tokens from {} queries", 
              assembled_context.total_tokens_used, assembled_context.results.len());

        // Phase 4: State Update (analyze and update world state)
        debug!("Phase 4: Updating world state based on assembled context");
        let phase_timer = tracker.start_phase_timing("state_update");
        let state_update_start = std::time::Instant::now();
        
        let state_update_result = self.state_update_service.update_world_state(
            &assembled_context,
            &request.user_query,
            request.user_id,
            request.chronicle_id,
        ).await?;
        
        let state_update_duration = state_update_start.elapsed();
        phase_timer.finish(tracker);

        info!("World state updated: {} entities modified, {:.2} confidence", 
              state_update_result.entities_updated.len(), state_update_result.confidence);

        // Phase 5: Context Optimization
        debug!("Phase 5: Optimizing context for token budget");
        let phase_timer = tracker.start_phase_timing("context_optimization");
        let optimization_start = std::time::Instant::now();
        
        let optimization = self.optimization_service.optimize_context(
            &assembled_context,
            request.token_budget,
            &request.user_query,
        ).await?;
        
        let optimization_duration = optimization_start.elapsed();
        phase_timer.finish(tracker);

        // Record AI call metrics for context optimization
        tracker.record_ai_call(AiCallMetric {
            call_purpose: "context_optimization".to_string(),
            response_time: optimization_duration,
            tokens_used: 400, // Estimated tokens
            success: true,
            model: "flash-lite".to_string(),
        });

        // Estimate token usage for optimization (Flash-Lite: ~300-500 tokens)
        token_usage.optimization_tokens = 400;
        token_usage.total_llm_tokens += token_usage.optimization_tokens;

        token_usage.final_tokens_used = optimization.total_estimated_tokens;

        info!("Context optimized: {} entities, {} pruned items, final tokens: {}", 
              optimization.optimized_entities.len(), 
              optimization.pruned_content.len(),
              optimization.total_estimated_tokens);

        // Phase 6: Generate Final Context String
        debug!("Phase 6: Generating final context string");
        let phase_timer = tracker.start_phase_timing("final_formatting");
        let formatting_start = std::time::Instant::now();
        
        let optimized_context = self.build_final_context_string(&optimization, &assembled_context)?;
        
        let formatting_duration = formatting_start.elapsed();
        phase_timer.finish(tracker);

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

        // Update token usage in tracker
        tracker.update_token_usage(TokenUsageEntry {
            intent_detection: token_usage.intent_detection_tokens,
            strategy_planning: token_usage.strategy_planning_tokens,
            context_optimization: token_usage.optimization_tokens,
            total_llm: token_usage.total_llm_tokens,
            context_generated: token_usage.context_tokens_generated,
            final_tokens: token_usage.final_tokens_used,
            budget_utilization: (token_usage.final_tokens_used as f32 / request.token_budget as f32) * 100.0,
        });

        let final_confidence = intent.confidence.min(optimization.confidence);

        let response = AgenticResponse {
            optimized_context,
            execution_summary,
            token_usage: token_usage.clone(),
            confidence: final_confidence,
        };

        // Token usage and response is handled by the outer method

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
            user_dek: None, // No DEK available in simple query
        };

        let response = self.process_query(request).await?;
        Ok(response.optimized_context)
    }

    /// Get current metrics from the orchestrator
    pub async fn get_metrics(&self) -> crate::services::agentic_metrics::AgenticMetrics {
        self.metrics_collector.get_current_metrics().await
    }

    /// Force metrics aggregation
    pub async fn aggregate_metrics(&self) -> Result<(), AppError> {
        self.metrics_collector.aggregate_metrics().await
    }

    /// Get token optimization insights and recommendations
    pub async fn get_token_optimization_insights(&self) -> crate::services::agentic_metrics::TokenOptimizationInsights {
        self.metrics_collector.get_token_optimization_insights().await
    }
}