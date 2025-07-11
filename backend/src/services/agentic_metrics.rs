use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use tracing::info;
use uuid::Uuid;

use crate::services::agentic_orchestrator::QualityMode;

/// Comprehensive metrics for agentic processing performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticMetrics {
    /// Total processing metrics
    pub processing_stats: ProcessingStats,
    /// Cache performance metrics
    pub cache_stats: CacheStats,
    /// Token usage analytics
    pub token_analytics: TokenAnalytics,
    /// Quality and success metrics
    pub quality_metrics: QualityMetrics,
    /// Timing breakdowns
    pub timing_metrics: TimingMetrics,
    /// Error and failure tracking
    pub error_metrics: ErrorMetrics,
    /// Performance trends over time
    pub trend_data: TrendData,
}

/// Core processing statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingStats {
    /// Total number of requests processed
    pub total_requests: u64,
    /// Number of successful responses
    pub successful_responses: u64,
    /// Number of failed requests
    pub failed_requests: u64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// P95 response time in milliseconds
    pub p95_response_time_ms: f64,
    /// P99 response time in milliseconds
    pub p99_response_time_ms: f64,
    /// Success rate as percentage
    pub success_rate: f64,
    /// Quality mode distribution
    pub quality_mode_distribution: HashMap<String, u64>,
    /// Average confidence score
    pub avg_confidence: f64,
    /// Time period for these stats
    pub stats_period: StatsPeriod,
}

/// Cache performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total cache lookups attempted
    pub total_lookups: u64,
    /// Number of cache hits
    pub cache_hits: u64,
    /// Number of cache misses
    pub cache_misses: u64,
    /// Cache hit rate as percentage
    pub hit_rate: f64,
    /// Cache miss rate as percentage
    pub miss_rate: f64,
    /// Average time saved per hit (ms)
    pub avg_time_saved_per_hit_ms: f64,
    /// Total time saved by caching (ms)
    pub total_time_saved_ms: f64,
    /// Cache size utilization
    pub cache_utilization: f64,
    /// Cache eviction statistics
    pub eviction_stats: EvictionStats,
    /// Hit rate by query type
    pub hit_rate_by_type: HashMap<String, f64>,
}

/// Cache eviction statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvictionStats {
    /// Total number of entries evicted
    pub total_evictions: u64,
    /// Evictions due to TTL expiry
    pub ttl_evictions: u64,
    /// Evictions due to LRU policy
    pub lru_evictions: u64,
    /// Evictions due to manual invalidation
    pub manual_evictions: u64,
    /// Average lifetime of evicted entries (minutes)
    pub avg_evicted_lifetime_minutes: f64,
}

/// Token usage analytics and optimization insights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAnalytics {
    /// Total tokens consumed across all requests
    pub total_tokens_consumed: u64,
    /// Average tokens per request
    pub avg_tokens_per_request: f64,
    /// Token usage breakdown by phase
    pub tokens_by_phase: TokenBreakdown,
    /// Token efficiency metrics
    pub efficiency_metrics: TokenEfficiency,
    /// Budget utilization statistics
    pub budget_utilization: BudgetUtilization,
    /// Token cost estimation (if available)
    pub estimated_cost_usd: Option<f64>,
}

/// Token usage breakdown by processing phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBreakdown {
    /// Tokens used for intent detection
    pub intent_detection: u64,
    /// Tokens used for strategy planning
    pub strategy_planning: u64,
    /// Tokens used for context optimization
    pub context_optimization: u64,
    /// Tokens used for other AI calls
    pub other_ai_calls: u64,
    /// Total LLM tokens across all phases
    pub total_llm_tokens: u64,
    /// Tokens generated for final context
    pub context_generation: u64,
}

/// Token efficiency and optimization metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEfficiency {
    /// Average token reduction through optimization
    pub avg_optimization_reduction: f64,
    /// Percentage of requests that hit token budget limits
    pub budget_constrained_percentage: f64,
    /// Average context pruning efficiency
    pub avg_pruning_efficiency: f64,
    /// Token reuse rate through caching
    pub token_reuse_rate: f64,
}

/// Budget utilization statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetUtilization {
    /// Average percentage of budget used
    pub avg_budget_used_percentage: f64,
    /// Percentage of requests that used full budget
    pub full_budget_usage_percentage: f64,
    /// Average unused budget per request
    pub avg_unused_budget: f64,
    /// Budget allocation efficiency
    pub allocation_efficiency: f64,
}

/// Quality and success metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    /// Average confidence score across all responses
    pub avg_confidence_score: f64,
    /// Distribution of confidence scores
    pub confidence_distribution: ConfidenceDistribution,
    /// Quality mode effectiveness
    pub quality_mode_effectiveness: HashMap<String, QualityModeStats>,
    /// Average entities analyzed per request
    pub avg_entities_analyzed: f64,
    /// Average queries executed per request
    pub avg_queries_executed: f64,
    /// Content pruning effectiveness
    pub pruning_effectiveness: f64,
}

/// Distribution of confidence scores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceDistribution {
    /// High confidence responses (>0.8)
    pub high_confidence_count: u64,
    /// Medium confidence responses (0.5-0.8)
    pub medium_confidence_count: u64,
    /// Low confidence responses (<0.5)
    pub low_confidence_count: u64,
    /// Percentage breakdown
    pub high_confidence_percentage: f64,
    pub medium_confidence_percentage: f64,
    pub low_confidence_percentage: f64,
}

/// Quality mode performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityModeStats {
    /// Number of requests in this mode
    pub request_count: u64,
    /// Average response time for this mode
    pub avg_response_time_ms: f64,
    /// Average confidence for this mode
    pub avg_confidence: f64,
    /// Average token usage for this mode
    pub avg_token_usage: f64,
    /// Success rate for this mode
    pub success_rate: f64,
}

/// Detailed timing metrics for performance analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingMetrics {
    /// Phase-by-phase timing breakdown
    pub phase_timing: PhaseTimingBreakdown,
    /// Database query timing statistics
    pub db_timing: DatabaseTiming,
    /// AI API call timing statistics
    pub ai_timing: AiTiming,
    /// Cache operation timing
    pub cache_timing: CacheTiming,
    /// Overall processing timing percentiles
    pub processing_percentiles: TimingPercentiles,
}

/// Timing breakdown by processing phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseTimingBreakdown {
    /// Average time for intent detection (ms)
    pub avg_intent_detection_ms: f64,
    /// Average time for strategy planning (ms)
    pub avg_strategy_planning_ms: f64,
    /// Average time for context assembly (ms)
    pub avg_context_assembly_ms: f64,
    /// Average time for context optimization (ms)
    pub avg_context_optimization_ms: f64,
    /// Average time for final formatting (ms)
    pub avg_final_formatting_ms: f64,
}

/// Database operation timing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseTiming {
    /// Average database query time (ms)
    pub avg_query_time_ms: f64,
    /// P95 database query time (ms)
    pub p95_query_time_ms: f64,
    /// Total database queries executed
    pub total_queries: u64,
    /// Average queries per request
    pub avg_queries_per_request: f64,
}

/// AI API call timing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTiming {
    /// Average AI API response time (ms)
    pub avg_ai_response_ms: f64,
    /// P95 AI API response time (ms)
    pub p95_ai_response_ms: f64,
    /// Total AI API calls made
    pub total_ai_calls: u64,
    /// Average AI calls per request
    pub avg_ai_calls_per_request: f64,
    /// AI API error rate
    pub ai_error_rate: f64,
}

/// Cache operation timing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheTiming {
    /// Average cache lookup time (ms)
    pub avg_lookup_time_ms: f64,
    /// Average cache store time (ms)
    pub avg_store_time_ms: f64,
    /// Cache operation success rate
    pub cache_operation_success_rate: f64,
}

/// Response time percentiles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingPercentiles {
    /// 50th percentile (median) response time
    pub p50_ms: f64,
    /// 75th percentile response time
    pub p75_ms: f64,
    /// 90th percentile response time
    pub p90_ms: f64,
    /// 95th percentile response time
    pub p95_ms: f64,
    /// 99th percentile response time
    pub p99_ms: f64,
    /// 99.9th percentile response time
    pub p999_ms: f64,
}

/// Error and failure tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorMetrics {
    /// Total number of errors
    pub total_errors: u64,
    /// Error breakdown by type
    pub error_types: HashMap<String, u64>,
    /// Error breakdown by phase
    pub errors_by_phase: HashMap<String, u64>,
    /// Error rate as percentage
    pub error_rate: f64,
    /// Average time to failure (ms)
    pub avg_time_to_failure_ms: f64,
    /// Recovery statistics
    pub recovery_stats: RecoveryStats,
}

/// Error recovery statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryStats {
    /// Number of successful recoveries
    pub successful_recoveries: u64,
    /// Number of failed recoveries
    pub failed_recoveries: u64,
    /// Average recovery time (ms)
    pub avg_recovery_time_ms: f64,
    /// Recovery success rate
    pub recovery_success_rate: f64,
}

/// Performance trends over time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendData {
    /// Time series data points
    pub data_points: Vec<TrendDataPoint>,
    /// Trend analysis results
    pub trend_analysis: TrendAnalysis,
    /// Performance predictions
    pub predictions: Option<PerformancePredictions>,
}

/// Individual trend data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendDataPoint {
    /// Timestamp for this data point
    pub timestamp: DateTime<Utc>,
    /// Request volume at this time
    pub request_volume: u64,
    /// Average response time at this time
    pub avg_response_time_ms: f64,
    /// Error rate at this time
    pub error_rate: f64,
    /// Cache hit rate at this time
    pub cache_hit_rate: f64,
    /// Average confidence at this time
    pub avg_confidence: f64,
}

/// Trend analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendAnalysis {
    /// Overall performance trend direction
    pub performance_trend: TrendDirection,
    /// Response time trend
    pub response_time_trend: TrendDirection,
    /// Error rate trend
    pub error_rate_trend: TrendDirection,
    /// Cache efficiency trend
    pub cache_efficiency_trend: TrendDirection,
    /// Quality trend
    pub quality_trend: TrendDirection,
}

/// Trend direction indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrendDirection {
    Improving,
    Stable,
    Degrading,
    Insufficient_Data,
}

/// Performance predictions based on trends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformancePredictions {
    /// Predicted response time in 1 hour
    pub predicted_response_time_1h: f64,
    /// Predicted error rate in 1 hour
    pub predicted_error_rate_1h: f64,
    /// Predicted cache hit rate in 1 hour
    pub predicted_cache_hit_rate_1h: f64,
    /// Confidence in predictions
    pub prediction_confidence: f64,
}

/// Time period for statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsPeriod {
    /// Start of the stats period
    pub start_time: DateTime<Utc>,
    /// End of the stats period
    pub end_time: DateTime<Utc>,
    /// Duration of the stats period
    pub duration_minutes: i64,
}

/// Individual measurement for performance tracking
#[derive(Debug, Clone)]
pub struct PerformanceMeasurement {
    /// Request ID for correlation
    pub request_id: Uuid,
    /// When the request started
    pub start_time: Instant,
    /// User ID making the request
    pub user_id: Uuid,
    /// Quality mode used
    pub quality_mode: QualityMode,
    /// Token budget allocated
    pub token_budget: u32,
    /// Phase timing measurements
    pub phase_timings: HashMap<String, Duration>,
    /// Cache hit/miss information
    pub cache_operations: Vec<CacheOperation>,
    /// Token usage breakdown
    pub token_usage: TokenUsageEntry,
    /// Whether the request succeeded
    pub success: bool,
    /// Final confidence score
    pub confidence: Option<f32>,
    /// Error information if failed
    pub error_info: Option<ErrorInfo>,
    /// AI API call metrics
    pub ai_calls: Vec<AiCallMetric>,
    /// Database query metrics
    pub db_queries: Vec<DbQueryMetric>,
}

/// Cache operation record
#[derive(Debug, Clone)]
pub struct CacheOperation {
    /// Type of cache operation
    pub operation_type: CacheOperationType,
    /// Query type for the cache operation
    pub query_type: String,
    /// Whether it was a hit or miss
    pub result: CacheResult,
    /// Time taken for the operation
    pub duration: Duration,
    /// Size of cached data (if applicable)
    pub data_size_bytes: Option<usize>,
}

/// Type of cache operation
#[derive(Debug, Clone)]
pub enum CacheOperationType {
    Lookup,
    Store,
    Invalidate,
    Evict,
}

/// Cache operation result
#[derive(Debug, Clone)]
pub enum CacheResult {
    Hit,
    Miss,
    Store_Success,
    Store_Failed,
    Invalidated,
    Evicted,
}

/// Token usage entry for a single request
#[derive(Debug, Clone)]
pub struct TokenUsageEntry {
    /// Tokens used for intent detection
    pub intent_detection: u32,
    /// Tokens used for strategy planning
    pub strategy_planning: u32,
    /// Tokens used for context optimization
    pub context_optimization: u32,
    /// Total LLM tokens
    pub total_llm: u32,
    /// Context tokens generated
    pub context_generated: u32,
    /// Final tokens used
    pub final_tokens: u32,
    /// Budget utilization percentage
    pub budget_utilization: f32,
}

/// Error information
#[derive(Debug, Clone)]
pub struct ErrorInfo {
    /// Error type/category
    pub error_type: String,
    /// Phase where error occurred
    pub error_phase: String,
    /// Error message
    pub error_message: String,
    /// Whether recovery was attempted
    pub recovery_attempted: bool,
    /// Whether recovery succeeded
    pub recovery_success: bool,
}

/// AI API call metric
#[derive(Debug, Clone)]
pub struct AiCallMetric {
    /// Purpose of the AI call
    pub call_purpose: String,
    /// Response time
    pub response_time: Duration,
    /// Tokens used in the call
    pub tokens_used: u32,
    /// Whether the call succeeded
    pub success: bool,
    /// Model used for the call
    pub model: String,
}

/// Database query metric
#[derive(Debug, Clone)]
pub struct DbQueryMetric {
    /// Type of query
    pub query_type: String,
    /// Response time
    pub response_time: Duration,
    /// Number of results returned
    pub result_count: usize,
    /// Whether the query succeeded
    pub success: bool,
}

/// Metrics collector and analyzer
pub struct AgenticMetricsCollector {
    /// Recent measurements for analysis
    measurements: Arc<RwLock<Vec<PerformanceMeasurement>>>,
    /// Aggregated metrics
    current_metrics: Arc<RwLock<AgenticMetrics>>,
    /// Configuration
    config: MetricsConfig,
}

/// Configuration for metrics collection
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// How many recent measurements to keep
    pub max_measurements: usize,
    /// How often to aggregate metrics
    pub aggregation_interval_minutes: u64,
    /// Whether to track detailed timing
    pub track_detailed_timing: bool,
    /// Whether to track token usage
    pub track_token_usage: bool,
    /// Whether to track cache metrics
    pub track_cache_metrics: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            max_measurements: 10000,
            aggregation_interval_minutes: 5,
            track_detailed_timing: true,
            track_token_usage: true,
            track_cache_metrics: true,
        }
    }
}

impl AgenticMetricsCollector {
    /// Create a new metrics collector
    pub fn new(config: MetricsConfig) -> Self {
        Self {
            measurements: Arc::new(RwLock::new(Vec::new())),
            current_metrics: Arc::new(RwLock::new(Self::empty_metrics())),
            config,
        }
    }

    /// Get token optimization insights and recommendations
    pub async fn get_token_optimization_insights(&self) -> TokenOptimizationInsights {
        let measurements = self.measurements.read().await;
        if measurements.is_empty() {
            return TokenOptimizationInsights::empty();
        }

        let analytics = self.calculate_token_analytics(&measurements);
        let recommendations = self.generate_optimization_recommendations(&analytics, &measurements);
        
        TokenOptimizationInsights {
            analytics,
            recommendations,
            cost_analysis: self.calculate_cost_analysis(&measurements),
            efficiency_trends: self.calculate_efficiency_trends(&measurements),
        }
    }

    /// Generate optimization recommendations based on token analytics
    fn generate_optimization_recommendations(
        &self,
        analytics: &TokenAnalytics,
        measurements: &[PerformanceMeasurement],
    ) -> Vec<TokenOptimizationRecommendation> {
        let mut recommendations = Vec::new();

        // Budget utilization recommendations
        if analytics.budget_utilization.avg_budget_used_percentage > 90.0 {
            recommendations.push(TokenOptimizationRecommendation {
                priority: RecommendationPriority::High,
                category: OptimizationCategory::BudgetManagement,
                title: "Increase token budgets for better performance".to_string(),
                description: format!(
                    "Average budget utilization is {:.1}%. Consider increasing budgets to avoid constraints.",
                    analytics.budget_utilization.avg_budget_used_percentage
                ),
                potential_savings: PotentialSavings {
                    tokens_per_request: 0,
                    cost_reduction_percentage: 0.0,
                    performance_improvement: Some("Reduced response time and better quality".to_string()),
                },
                implementation_effort: ImplementationEffort::Low,
            });
        }

        if analytics.budget_utilization.avg_budget_used_percentage < 60.0 {
            let potential_reduction = (analytics.budget_utilization.avg_unused_budget * 0.3) as u32;
            recommendations.push(TokenOptimizationRecommendation {
                priority: RecommendationPriority::Medium,
                category: OptimizationCategory::BudgetManagement,
                title: "Reduce token budgets to optimize costs".to_string(),
                description: format!(
                    "Average budget utilization is only {:.1}%. Consider reducing budgets by ~30%.",
                    analytics.budget_utilization.avg_budget_used_percentage
                ),
                potential_savings: PotentialSavings {
                    tokens_per_request: potential_reduction,
                    cost_reduction_percentage: 30.0,
                    performance_improvement: None,
                },
                implementation_effort: ImplementationEffort::Low,
            });
        }

        // Cache optimization recommendations
        if analytics.efficiency_metrics.token_reuse_rate < 30.0 {
            recommendations.push(TokenOptimizationRecommendation {
                priority: RecommendationPriority::High,
                category: OptimizationCategory::Caching,
                title: "Improve caching strategy for better token reuse".to_string(),
                description: format!(
                    "Token reuse rate is only {:.1}%. Optimize cache TTL and invalidation strategies.",
                    analytics.efficiency_metrics.token_reuse_rate
                ),
                potential_savings: PotentialSavings {
                    tokens_per_request: (analytics.avg_tokens_per_request * 0.2) as u32,
                    cost_reduction_percentage: 20.0,
                    performance_improvement: Some("Faster response times through cached results".to_string()),
                },
                implementation_effort: ImplementationEffort::Medium,
            });
        }

        // Context optimization recommendations
        if analytics.efficiency_metrics.avg_optimization_reduction < 10.0 {
            recommendations.push(TokenOptimizationRecommendation {
                priority: RecommendationPriority::Medium,
                category: OptimizationCategory::ContextOptimization,
                title: "Improve context pruning algorithms".to_string(),
                description: format!(
                    "Context optimization is only reducing tokens by {:.1}%. Enhance pruning logic.",
                    analytics.efficiency_metrics.avg_optimization_reduction
                ),
                potential_savings: PotentialSavings {
                    tokens_per_request: (analytics.avg_tokens_per_request * 0.15) as u32,
                    cost_reduction_percentage: 15.0,
                    performance_improvement: Some("More focused context for better AI responses".to_string()),
                },
                implementation_effort: ImplementationEffort::High,
            });
        }

        // Phase-specific recommendations
        let intent_percentage = (analytics.tokens_by_phase.intent_detection as f64 / analytics.tokens_by_phase.total_llm_tokens as f64) * 100.0;
        if intent_percentage > 25.0 {
            recommendations.push(TokenOptimizationRecommendation {
                priority: RecommendationPriority::Medium,
                category: OptimizationCategory::PhaseOptimization,
                title: "Optimize intent detection phase".to_string(),
                description: format!(
                    "Intent detection uses {:.1}% of total tokens. Consider using a more efficient model.",
                    intent_percentage
                ),
                potential_savings: PotentialSavings {
                    tokens_per_request: (analytics.tokens_by_phase.intent_detection as f64 * 0.4) as u32,
                    cost_reduction_percentage: intent_percentage * 0.4,
                    performance_improvement: Some("Faster intent detection with maintained accuracy".to_string()),
                },
                implementation_effort: ImplementationEffort::Medium,
            });
        }

        // Quality mode recommendations
        let high_quality_usage = measurements.iter()
            .filter(|m| matches!(m.quality_mode, QualityMode::Thorough))
            .count() as f64 / measurements.len() as f64 * 100.0;
        
        if high_quality_usage > 50.0 {
            recommendations.push(TokenOptimizationRecommendation {
                priority: RecommendationPriority::Low,
                category: OptimizationCategory::QualityModeOptimization,
                title: "Review quality mode usage patterns".to_string(),
                description: format!(
                    "{:.1}% of requests use Thorough mode. Evaluate if Balanced mode is sufficient.",
                    high_quality_usage
                ),
                potential_savings: PotentialSavings {
                    tokens_per_request: (analytics.avg_tokens_per_request * 0.25) as u32,
                    cost_reduction_percentage: 25.0,
                    performance_improvement: Some("Faster responses with minimal quality impact".to_string()),
                },
                implementation_effort: ImplementationEffort::Low,
            });
        }

        recommendations
    }

    /// Calculate cost analysis for token usage
    fn calculate_cost_analysis(&self, measurements: &[PerformanceMeasurement]) -> CostAnalysis {
        let total_tokens: u64 = measurements.iter()
            .map(|m| m.token_usage.total_llm as u64)
            .sum();

        let total_requests = measurements.len() as u64;
        let cost_per_1k_tokens = 0.002; // Rough estimate
        let current_monthly_cost = (total_tokens as f64 / 1000.0) * cost_per_1k_tokens * 30.0; // Extrapolate to monthly

        // Calculate potential savings
        let avg_optimization_reduction = measurements.iter()
            .filter_map(|m| {
                let initial = m.token_usage.context_generated;
                let final_tokens = m.token_usage.final_tokens;
                if initial > 0 && final_tokens < initial {
                    Some((initial - final_tokens) as f64 / initial as f64)
                } else {
                    None
                }
            })
            .fold(0.0, |acc, x| acc + x) / measurements.len() as f64;

        let potential_monthly_savings = current_monthly_cost * avg_optimization_reduction;

        CostAnalysis {
            current_monthly_cost_estimate: current_monthly_cost,
            potential_monthly_savings: potential_monthly_savings,
            cost_per_request: current_monthly_cost / (total_requests as f64).max(1.0),
            cost_breakdown_by_phase: CostBreakdownByPhase {
                intent_detection_cost: (measurements.iter().map(|m| m.token_usage.intent_detection as u64).sum::<u64>() as f64 / 1000.0) * cost_per_1k_tokens,
                strategy_planning_cost: (measurements.iter().map(|m| m.token_usage.strategy_planning as u64).sum::<u64>() as f64 / 1000.0) * cost_per_1k_tokens,
                context_optimization_cost: (measurements.iter().map(|m| m.token_usage.context_optimization as u64).sum::<u64>() as f64 / 1000.0) * cost_per_1k_tokens,
            },
            roi_analysis: ROIAnalysis {
                performance_improvement_value: potential_monthly_savings * 2.0, // Assume 2x value from improved performance
                implementation_cost_estimate: 0.0, // Would need to be calculated based on development time
                payback_period_months: 1.0, // Most optimizations pay back quickly
            },
        }
    }

    /// Calculate efficiency trends over time
    fn calculate_efficiency_trends(&self, measurements: &[PerformanceMeasurement]) -> EfficiencyTrends {
        // For now, return stable trends - would implement time-series analysis
        EfficiencyTrends {
            token_usage_trend: TrendDirection::Stable,
            optimization_effectiveness_trend: TrendDirection::Improving,
            cache_hit_rate_trend: TrendDirection::Stable,
            budget_utilization_trend: TrendDirection::Stable,
            cost_efficiency_trend: TrendDirection::Improving,
        }
    }

    /// Start tracking a new request
    pub async fn start_request_tracking(
        &self,
        user_id: Uuid,
        quality_mode: QualityMode,
        token_budget: u32,
    ) -> RequestTracker {
        let request_id = Uuid::new_v4();
        RequestTracker {
            request_id,
            start_time: Instant::now(),
            user_id,
            quality_mode,
            token_budget,
            phase_timings: HashMap::new(),
            cache_operations: Vec::new(),
            token_usage: TokenUsageEntry {
                intent_detection: 0,
                strategy_planning: 0,
                context_optimization: 0,
                total_llm: 0,
                context_generated: 0,
                final_tokens: 0,
                budget_utilization: 0.0,
            },
            ai_calls: Vec::new(),
            db_queries: Vec::new(),
        }
    }

    /// Record a completed request
    pub async fn record_request_completion(
        &self,
        tracker: RequestTracker,
        success: bool,
        confidence: Option<f32>,
        error_info: Option<ErrorInfo>,
    ) -> Result<(), crate::errors::AppError> {
        let measurement = PerformanceMeasurement {
            request_id: tracker.request_id,
            start_time: tracker.start_time,
            user_id: tracker.user_id,
            quality_mode: tracker.quality_mode,
            token_budget: tracker.token_budget,
            phase_timings: tracker.phase_timings,
            cache_operations: tracker.cache_operations,
            token_usage: tracker.token_usage,
            success,
            confidence,
            error_info,
            ai_calls: tracker.ai_calls,
            db_queries: tracker.db_queries,
        };

        // Add to measurements
        {
            let mut measurements = self.measurements.write().await;
            measurements.push(measurement);

            // Limit size to prevent memory growth
            let len = measurements.len();
            if len > self.config.max_measurements {
                measurements.drain(0..len - self.config.max_measurements);
            }
        }

        // Trigger aggregation if needed
        self.maybe_aggregate_metrics().await?;

        Ok(())
    }

    /// Get current aggregated metrics
    pub async fn get_current_metrics(&self) -> AgenticMetrics {
        self.current_metrics.read().await.clone()
    }

    /// Force metrics aggregation
    pub async fn aggregate_metrics(&self) -> Result<(), crate::errors::AppError> {
        let measurements = self.measurements.read().await;
        let new_metrics = self.calculate_metrics(&measurements).await?;
        
        *self.current_metrics.write().await = new_metrics;
        
        info!("Aggregated metrics for {} measurements", measurements.len());
        Ok(())
    }

    /// Maybe aggregate metrics based on timing
    async fn maybe_aggregate_metrics(&self) -> Result<(), crate::errors::AppError> {
        // For now, aggregate on every measurement
        // In production, this would be time-based
        self.aggregate_metrics().await
    }

    /// Calculate aggregated metrics from measurements
    async fn calculate_metrics(
        &self,
        measurements: &[PerformanceMeasurement],
    ) -> Result<AgenticMetrics, crate::errors::AppError> {
        if measurements.is_empty() {
            return Ok(Self::empty_metrics());
        }

        // Calculate all the different metric categories
        let processing_stats = self.calculate_processing_stats(measurements);
        let cache_stats = self.calculate_cache_stats(measurements);
        let token_analytics = self.calculate_token_analytics(measurements);
        
        // Use empty metrics for now as placeholder - this can be enhanced later
        let empty_metrics = Self::empty_metrics();
        let quality_metrics = empty_metrics.quality_metrics;
        let timing_metrics = empty_metrics.timing_metrics;
        let error_metrics = empty_metrics.error_metrics;
        let trend_data = empty_metrics.trend_data;

        Ok(AgenticMetrics {
            processing_stats,
            cache_stats,
            token_analytics,
            quality_metrics,
            timing_metrics,
            error_metrics,
            trend_data,
        })
    }

    /// Calculate detailed token usage analytics for optimization
    fn calculate_token_analytics(&self, measurements: &[PerformanceMeasurement]) -> TokenAnalytics {
        if measurements.is_empty() {
            return TokenAnalytics {
                total_tokens_consumed: 0,
                avg_tokens_per_request: 0.0,
                tokens_by_phase: TokenBreakdown {
                    intent_detection: 0,
                    strategy_planning: 0,
                    context_optimization: 0,
                    other_ai_calls: 0,
                    total_llm_tokens: 0,
                    context_generation: 0,
                },
                efficiency_metrics: TokenEfficiency {
                    avg_optimization_reduction: 0.0,
                    budget_constrained_percentage: 0.0,
                    avg_pruning_efficiency: 0.0,
                    token_reuse_rate: 0.0,
                },
                budget_utilization: BudgetUtilization {
                    avg_budget_used_percentage: 0.0,
                    full_budget_usage_percentage: 0.0,
                    avg_unused_budget: 0.0,
                    allocation_efficiency: 0.0,
                },
                estimated_cost_usd: None,
            };
        }

        let total_requests = measurements.len() as f64;
        
        // Calculate token breakdown by phase
        let mut total_intent_detection = 0u64;
        let mut total_strategy_planning = 0u64;
        let mut total_context_optimization = 0u64;
        let mut total_llm_tokens = 0u64;
        let mut total_context_generation = 0u64;
        
        // Budget and efficiency tracking
        let mut total_budget_allocated = 0u64;
        let mut total_budget_used = 0u64;
        let mut budget_constrained_count = 0u64;
        let mut full_budget_usage_count = 0u64;
        let mut successful_optimizations = 0u64;
        let mut total_optimization_reduction = 0.0f64;
        
        // Token reuse calculation (based on cache hits)
        let mut total_cache_operations = 0u64;
        let mut successful_cache_hits = 0u64;
        
        for measurement in measurements {
            let token_usage = &measurement.token_usage;
            
            // Accumulate token usage by phase
            total_intent_detection += token_usage.intent_detection as u64;
            total_strategy_planning += token_usage.strategy_planning as u64;
            total_context_optimization += token_usage.context_optimization as u64;
            total_llm_tokens += token_usage.total_llm as u64;
            total_context_generation += token_usage.context_generated as u64;
            
            // Budget analysis
            total_budget_allocated += measurement.token_budget as u64;
            total_budget_used += token_usage.final_tokens as u64;
            
            // Check if request was budget constrained (used >95% of budget)
            if token_usage.budget_utilization > 95.0 {
                budget_constrained_count += 1;
            }
            
            // Check if request used full budget (>99% utilization)
            if token_usage.budget_utilization > 99.0 {
                full_budget_usage_count += 1;
            }
            
            // Calculate optimization efficiency
            let initial_context_tokens = token_usage.context_generated;
            let final_tokens = token_usage.final_tokens;
            if initial_context_tokens > 0 && final_tokens < initial_context_tokens {
                successful_optimizations += 1;
                let reduction_ratio = (initial_context_tokens - final_tokens) as f64 / initial_context_tokens as f64;
                total_optimization_reduction += reduction_ratio;
            }
            
            // Count cache operations for reuse rate
            for cache_op in &measurement.cache_operations {
                total_cache_operations += 1;
                if matches!(cache_op.result, CacheResult::Hit) {
                    successful_cache_hits += 1;
                }
            }
        }

        // Calculate averages and percentages
        let avg_tokens_per_request = total_llm_tokens as f64 / total_requests;
        let avg_budget_used_percentage = if total_budget_allocated > 0 {
            (total_budget_used as f64 / total_budget_allocated as f64) * 100.0
        } else {
            0.0
        };
        
        let budget_constrained_percentage = (budget_constrained_count as f64 / total_requests) * 100.0;
        let full_budget_usage_percentage = (full_budget_usage_count as f64 / total_requests) * 100.0;
        
        let avg_optimization_reduction = if successful_optimizations > 0 {
            (total_optimization_reduction / successful_optimizations as f64) * 100.0
        } else {
            0.0
        };
        
        let token_reuse_rate = if total_cache_operations > 0 {
            (successful_cache_hits as f64 / total_cache_operations as f64) * 100.0
        } else {
            0.0
        };
        
        let avg_unused_budget = if total_requests > 0.0 {
            (total_budget_allocated - total_budget_used) as f64 / total_requests
        } else {
            0.0
        };
        
        // Calculate allocation efficiency (how well we use allocated budgets)
        let allocation_efficiency = if total_budget_allocated > 0 {
            // Higher efficiency when we use more of allocated budget without hitting limits
            let utilization_score = (total_budget_used as f64 / total_budget_allocated as f64) * 100.0;
            let penalty_for_constraints = budget_constrained_percentage * 0.5; // Penalize constrained requests
            (utilization_score - penalty_for_constraints).max(0.0).min(100.0)
        } else {
            0.0
        };
        
        // Estimate cost (rough calculation based on token usage)
        // Using rough estimates: GPT-3.5-turbo-like pricing
        let estimated_cost_usd = Some({
            let cost_per_1k_tokens = 0.002; // $0.002 per 1K tokens (rough estimate)
            (total_llm_tokens as f64 / 1000.0) * cost_per_1k_tokens
        });

        TokenAnalytics {
            total_tokens_consumed: total_llm_tokens,
            avg_tokens_per_request,
            tokens_by_phase: TokenBreakdown {
                intent_detection: total_intent_detection,
                strategy_planning: total_strategy_planning,
                context_optimization: total_context_optimization,
                other_ai_calls: 0, // We could track this separately in the future
                total_llm_tokens,
                context_generation: total_context_generation,
            },
            efficiency_metrics: TokenEfficiency {
                avg_optimization_reduction,
                budget_constrained_percentage,
                avg_pruning_efficiency: avg_optimization_reduction, // Same as optimization reduction for now
                token_reuse_rate,
            },
            budget_utilization: BudgetUtilization {
                avg_budget_used_percentage,
                full_budget_usage_percentage,
                avg_unused_budget,
                allocation_efficiency,
            },
            estimated_cost_usd,
        }
    }

    /// Calculate processing statistics
    fn calculate_processing_stats(&self, measurements: &[PerformanceMeasurement]) -> ProcessingStats {
        if measurements.is_empty() {
            return ProcessingStats {
                total_requests: 0,
                successful_responses: 0,
                failed_requests: 0,
                avg_response_time_ms: 0.0,
                p95_response_time_ms: 0.0,
                p99_response_time_ms: 0.0,
                success_rate: 0.0,
                quality_mode_distribution: HashMap::new(),
                avg_confidence: 0.0,
                stats_period: StatsPeriod {
                    start_time: Utc::now(),
                    end_time: Utc::now(),
                    duration_minutes: 0,
                },
            };
        }

        let total_requests = measurements.len() as u64;
        let successful_responses = measurements.iter().filter(|m| m.success).count() as u64;
        let failed_requests = total_requests - successful_responses;
        let success_rate = (successful_responses as f64 / total_requests as f64) * 100.0;

        // Calculate response times
        let mut response_times: Vec<f64> = measurements
            .iter()
            .map(|m| m.start_time.elapsed().as_millis() as f64)
            .collect();
        response_times.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let avg_response_time_ms = response_times.iter().sum::<f64>() / response_times.len() as f64;
        let p95_index = ((response_times.len() as f64) * 0.95) as usize;
        let p99_index = ((response_times.len() as f64) * 0.99) as usize;
        let p95_response_time_ms = response_times.get(p95_index).copied().unwrap_or(0.0);
        let p99_response_time_ms = response_times.get(p99_index).copied().unwrap_or(0.0);

        // Quality mode distribution
        let mut quality_mode_distribution = HashMap::new();
        for measurement in measurements {
            let mode_str = format!("{:?}", measurement.quality_mode);
            *quality_mode_distribution.entry(mode_str).or_insert(0) += 1;
        }

        // Average confidence
        let confidence_values: Vec<f32> = measurements
            .iter()
            .filter_map(|m| m.confidence)
            .collect();
        let avg_confidence = if !confidence_values.is_empty() {
            confidence_values.iter().sum::<f32>() / confidence_values.len() as f32
        } else {
            0.0
        } as f64;

        // Calculate stats period
        let start_time = measurements
            .iter()
            .map(|m| DateTime::from_timestamp(m.start_time.elapsed().as_secs() as i64, 0).unwrap_or_else(|| Utc::now()))
            .min()
            .unwrap_or_else(|| Utc::now());
        let end_time = Utc::now();
        let duration_minutes = (end_time - start_time).num_minutes();

        ProcessingStats {
            total_requests,
            successful_responses,
            failed_requests,
            avg_response_time_ms,
            p95_response_time_ms,
            p99_response_time_ms,
            success_rate,
            quality_mode_distribution,
            avg_confidence,
            stats_period: StatsPeriod {
                start_time,
                end_time,
                duration_minutes,
            },
        }
    }

    /// Calculate cache statistics
    fn calculate_cache_stats(&self, measurements: &[PerformanceMeasurement]) -> CacheStats {
        let mut total_lookups = 0u64;
        let mut cache_hits = 0u64;
        let mut cache_misses = 0u64;
        let mut hit_times: Vec<f64> = Vec::new();
        let mut hit_rate_by_type: HashMap<String, (u64, u64)> = HashMap::new(); // (hits, total)

        for measurement in measurements {
            for cache_op in &measurement.cache_operations {
                if matches!(cache_op.operation_type, CacheOperationType::Lookup) {
                    total_lookups += 1;
                    let type_stats = hit_rate_by_type
                        .entry(cache_op.query_type.clone())
                        .or_insert((0, 0));
                    type_stats.1 += 1; // total lookups for this type
                    
                    match cache_op.result {
                        CacheResult::Hit => {
                            cache_hits += 1;
                            type_stats.0 += 1; // hits for this type
                            hit_times.push(cache_op.duration.as_millis() as f64);
                        }
                        CacheResult::Miss => {
                            cache_misses += 1;
                        }
                        _ => {}
                    }
                }
            }
        }

        let hit_rate = if total_lookups > 0 {
            (cache_hits as f64 / total_lookups as f64) * 100.0
        } else {
            0.0
        };
        let miss_rate = 100.0 - hit_rate;

        let avg_time_saved_per_hit_ms = if !hit_times.is_empty() {
            hit_times.iter().sum::<f64>() / hit_times.len() as f64
        } else {
            0.0
        };

        let total_time_saved_ms = avg_time_saved_per_hit_ms * cache_hits as f64;

        // Convert hit rate by type
        let hit_rate_by_type_final: HashMap<String, f64> = hit_rate_by_type
            .into_iter()
            .map(|(query_type, (hits, total))| {
                let rate = if total > 0 {
                    (hits as f64 / total as f64) * 100.0
                } else {
                    0.0
                };
                (query_type, rate)
            })
            .collect();

        CacheStats {
            total_lookups,
            cache_hits,
            cache_misses,
            hit_rate,
            miss_rate,
            avg_time_saved_per_hit_ms,
            total_time_saved_ms,
            cache_utilization: 0.0, // Would need cache size info
            eviction_stats: EvictionStats {
                total_evictions: 0,
                ttl_evictions: 0,
                lru_evictions: 0,
                manual_evictions: 0,
                avg_evicted_lifetime_minutes: 0.0,
            },
            hit_rate_by_type: hit_rate_by_type_final,
        }
    }

    /// Create empty metrics structure
    fn empty_metrics() -> AgenticMetrics {
        let now = Utc::now();
        AgenticMetrics {
            processing_stats: ProcessingStats {
                total_requests: 0,
                successful_responses: 0,
                failed_requests: 0,
                avg_response_time_ms: 0.0,
                p95_response_time_ms: 0.0,
                p99_response_time_ms: 0.0,
                success_rate: 0.0,
                quality_mode_distribution: HashMap::new(),
                avg_confidence: 0.0,
                stats_period: StatsPeriod {
                    start_time: now,
                    end_time: now,
                    duration_minutes: 0,
                },
            },
            cache_stats: CacheStats {
                total_lookups: 0,
                cache_hits: 0,
                cache_misses: 0,
                hit_rate: 0.0,
                miss_rate: 0.0,
                avg_time_saved_per_hit_ms: 0.0,
                total_time_saved_ms: 0.0,
                cache_utilization: 0.0,
                eviction_stats: EvictionStats {
                    total_evictions: 0,
                    ttl_evictions: 0,
                    lru_evictions: 0,
                    manual_evictions: 0,
                    avg_evicted_lifetime_minutes: 0.0,
                },
                hit_rate_by_type: HashMap::new(),
            },
            token_analytics: TokenAnalytics {
                total_tokens_consumed: 0,
                avg_tokens_per_request: 0.0,
                tokens_by_phase: TokenBreakdown {
                    intent_detection: 0,
                    strategy_planning: 0,
                    context_optimization: 0,
                    other_ai_calls: 0,
                    total_llm_tokens: 0,
                    context_generation: 0,
                },
                efficiency_metrics: TokenEfficiency {
                    avg_optimization_reduction: 0.0,
                    budget_constrained_percentage: 0.0,
                    avg_pruning_efficiency: 0.0,
                    token_reuse_rate: 0.0,
                },
                budget_utilization: BudgetUtilization {
                    avg_budget_used_percentage: 0.0,
                    full_budget_usage_percentage: 0.0,
                    avg_unused_budget: 0.0,
                    allocation_efficiency: 0.0,
                },
                estimated_cost_usd: None,
            },
            quality_metrics: QualityMetrics {
                avg_confidence_score: 0.0,
                confidence_distribution: ConfidenceDistribution {
                    high_confidence_count: 0,
                    medium_confidence_count: 0,
                    low_confidence_count: 0,
                    high_confidence_percentage: 0.0,
                    medium_confidence_percentage: 0.0,
                    low_confidence_percentage: 0.0,
                },
                quality_mode_effectiveness: HashMap::new(),
                avg_entities_analyzed: 0.0,
                avg_queries_executed: 0.0,
                pruning_effectiveness: 0.0,
            },
            timing_metrics: TimingMetrics {
                phase_timing: PhaseTimingBreakdown {
                    avg_intent_detection_ms: 0.0,
                    avg_strategy_planning_ms: 0.0,
                    avg_context_assembly_ms: 0.0,
                    avg_context_optimization_ms: 0.0,
                    avg_final_formatting_ms: 0.0,
                },
                db_timing: DatabaseTiming {
                    avg_query_time_ms: 0.0,
                    p95_query_time_ms: 0.0,
                    total_queries: 0,
                    avg_queries_per_request: 0.0,
                },
                ai_timing: AiTiming {
                    avg_ai_response_ms: 0.0,
                    p95_ai_response_ms: 0.0,
                    total_ai_calls: 0,
                    avg_ai_calls_per_request: 0.0,
                    ai_error_rate: 0.0,
                },
                cache_timing: CacheTiming {
                    avg_lookup_time_ms: 0.0,
                    avg_store_time_ms: 0.0,
                    cache_operation_success_rate: 0.0,
                },
                processing_percentiles: TimingPercentiles {
                    p50_ms: 0.0,
                    p75_ms: 0.0,
                    p90_ms: 0.0,
                    p95_ms: 0.0,
                    p99_ms: 0.0,
                    p999_ms: 0.0,
                },
            },
            error_metrics: ErrorMetrics {
                total_errors: 0,
                error_types: HashMap::new(),
                errors_by_phase: HashMap::new(),
                error_rate: 0.0,
                avg_time_to_failure_ms: 0.0,
                recovery_stats: RecoveryStats {
                    successful_recoveries: 0,
                    failed_recoveries: 0,
                    avg_recovery_time_ms: 0.0,
                    recovery_success_rate: 0.0,
                },
            },
            trend_data: TrendData {
                data_points: Vec::new(),
                trend_analysis: TrendAnalysis {
                    performance_trend: TrendDirection::Insufficient_Data,
                    response_time_trend: TrendDirection::Insufficient_Data,
                    error_rate_trend: TrendDirection::Insufficient_Data,
                    cache_efficiency_trend: TrendDirection::Insufficient_Data,
                    quality_trend: TrendDirection::Insufficient_Data,
                },
                predictions: None,
            },
        }
    }
}

/// Request tracker for collecting metrics during request processing
pub struct RequestTracker {
    pub request_id: Uuid,
    pub start_time: Instant,
    pub user_id: Uuid,
    pub quality_mode: QualityMode,
    pub token_budget: u32,
    pub phase_timings: HashMap<String, Duration>,
    pub cache_operations: Vec<CacheOperation>,
    pub token_usage: TokenUsageEntry,
    pub ai_calls: Vec<AiCallMetric>,
    pub db_queries: Vec<DbQueryMetric>,
}

impl RequestTracker {
    /// Start timing a phase
    pub fn start_phase_timing(&mut self, phase_name: &str) -> PhaseTimer {
        PhaseTimer {
            phase_name: phase_name.to_string(),
            start_time: Instant::now(),
        }
    }

    /// Record phase timing
    pub fn record_phase_timing(&mut self, phase_name: String, duration: Duration) {
        self.phase_timings.insert(phase_name, duration);
    }

    /// Record cache operation
    pub fn record_cache_operation(&mut self, operation: CacheOperation) {
        self.cache_operations.push(operation);
    }

    /// Update token usage
    pub fn update_token_usage(&mut self, usage: TokenUsageEntry) {
        self.token_usage = usage;
    }

    /// Record AI call
    pub fn record_ai_call(&mut self, ai_call: AiCallMetric) {
        self.ai_calls.push(ai_call);
    }

    /// Record DB query
    pub fn record_db_query(&mut self, db_query: DbQueryMetric) {
        self.db_queries.push(db_query);
    }
}

/// Timer for measuring phase durations
pub struct PhaseTimer {
    phase_name: String,
    start_time: Instant,
}

impl PhaseTimer {
    /// Finish timing and return the duration
    pub fn finish(self, tracker: &mut RequestTracker) {
        let duration = self.start_time.elapsed();
        tracker.record_phase_timing(self.phase_name, duration);
    }
}

/// Comprehensive token optimization insights and recommendations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenOptimizationInsights {
    /// Detailed token analytics
    pub analytics: TokenAnalytics,
    /// Actionable optimization recommendations
    pub recommendations: Vec<TokenOptimizationRecommendation>,
    /// Cost analysis and projections
    pub cost_analysis: CostAnalysis,
    /// Efficiency trends over time
    pub efficiency_trends: EfficiencyTrends,
}

impl TokenOptimizationInsights {
    pub fn empty() -> Self {
        Self {
            analytics: TokenAnalytics {
                total_tokens_consumed: 0,
                avg_tokens_per_request: 0.0,
                tokens_by_phase: TokenBreakdown {
                    intent_detection: 0,
                    strategy_planning: 0,
                    context_optimization: 0,
                    other_ai_calls: 0,
                    total_llm_tokens: 0,
                    context_generation: 0,
                },
                efficiency_metrics: TokenEfficiency {
                    avg_optimization_reduction: 0.0,
                    budget_constrained_percentage: 0.0,
                    avg_pruning_efficiency: 0.0,
                    token_reuse_rate: 0.0,
                },
                budget_utilization: BudgetUtilization {
                    avg_budget_used_percentage: 0.0,
                    full_budget_usage_percentage: 0.0,
                    avg_unused_budget: 0.0,
                    allocation_efficiency: 0.0,
                },
                estimated_cost_usd: None,
            },
            recommendations: Vec::new(),
            cost_analysis: CostAnalysis::empty(),
            efficiency_trends: EfficiencyTrends::stable(),
        }
    }
}

/// Actionable optimization recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenOptimizationRecommendation {
    /// Priority level for this recommendation
    pub priority: RecommendationPriority,
    /// Category of optimization
    pub category: OptimizationCategory,
    /// Short title describing the recommendation
    pub title: String,
    /// Detailed description and rationale
    pub description: String,
    /// Estimated potential savings
    pub potential_savings: PotentialSavings,
    /// Implementation effort required
    pub implementation_effort: ImplementationEffort,
}

/// Priority levels for optimization recommendations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RecommendationPriority {
    Critical,   // Immediate action required
    High,       // Important optimization
    Medium,     // Beneficial improvement
    Low,        // Nice to have
}

/// Categories of token optimizations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OptimizationCategory {
    BudgetManagement,        // Token budget allocation
    Caching,                 // Cache strategy optimization
    ContextOptimization,     // Context pruning and assembly
    PhaseOptimization,       // Individual phase efficiency
    QualityModeOptimization, // Quality vs efficiency tradeoffs
    ModelSelection,          // AI model choice optimization
}

/// Estimated potential savings from optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PotentialSavings {
    /// Token savings per request
    pub tokens_per_request: u32,
    /// Percentage cost reduction
    pub cost_reduction_percentage: f64,
    /// Expected performance improvement (if any)
    pub performance_improvement: Option<String>,
}

/// Implementation effort levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ImplementationEffort {
    Low,    // Configuration change or simple code update
    Medium, // Moderate development effort
    High,   // Significant development work required
}

/// Cost analysis and projections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostAnalysis {
    /// Estimated current monthly cost
    pub current_monthly_cost_estimate: f64,
    /// Potential monthly savings from optimizations
    pub potential_monthly_savings: f64,
    /// Average cost per request
    pub cost_per_request: f64,
    /// Cost breakdown by processing phase
    pub cost_breakdown_by_phase: CostBreakdownByPhase,
    /// ROI analysis for optimization efforts
    pub roi_analysis: ROIAnalysis,
}

impl CostAnalysis {
    pub fn empty() -> Self {
        Self {
            current_monthly_cost_estimate: 0.0,
            potential_monthly_savings: 0.0,
            cost_per_request: 0.0,
            cost_breakdown_by_phase: CostBreakdownByPhase {
                intent_detection_cost: 0.0,
                strategy_planning_cost: 0.0,
                context_optimization_cost: 0.0,
            },
            roi_analysis: ROIAnalysis {
                performance_improvement_value: 0.0,
                implementation_cost_estimate: 0.0,
                payback_period_months: 0.0,
            },
        }
    }
}

/// Cost breakdown by processing phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostBreakdownByPhase {
    /// Cost for intent detection phase
    pub intent_detection_cost: f64,
    /// Cost for strategy planning phase
    pub strategy_planning_cost: f64,
    /// Cost for context optimization phase
    pub context_optimization_cost: f64,
}

/// ROI analysis for optimization investments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ROIAnalysis {
    /// Estimated value of performance improvements
    pub performance_improvement_value: f64,
    /// Estimated cost to implement optimizations
    pub implementation_cost_estimate: f64,
    /// Expected payback period in months
    pub payback_period_months: f64,
}

/// Efficiency trends over time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfficiencyTrends {
    /// Overall token usage trend
    pub token_usage_trend: TrendDirection,
    /// Context optimization effectiveness trend
    pub optimization_effectiveness_trend: TrendDirection,
    /// Cache hit rate trend
    pub cache_hit_rate_trend: TrendDirection,
    /// Budget utilization trend
    pub budget_utilization_trend: TrendDirection,
    /// Cost efficiency trend
    pub cost_efficiency_trend: TrendDirection,
}

impl EfficiencyTrends {
    pub fn stable() -> Self {
        Self {
            token_usage_trend: TrendDirection::Stable,
            optimization_effectiveness_trend: TrendDirection::Stable,
            cache_hit_rate_trend: TrendDirection::Stable,
            budget_utilization_trend: TrendDirection::Stable,
            cost_efficiency_trend: TrendDirection::Stable,
        }
    }
}