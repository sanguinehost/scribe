//! Hybrid Query Router
//!
//! This module implements Phase 5.4 of the ECS Architecture Plan:
//! - Intelligent query routing based on system health and query characteristics
//! - Failure contracts with specific error modes and recovery strategies
//! - Circuit breaker patterns for different service dependencies
//! - Performance monitoring and adaptive routing decisions
//!
//! Key Features:
//! - Query complexity analysis and routing optimization
//! - Health-aware service selection (ECS vs Chronicle-only)
//! - Circuit breakers for ECS, RAG, and relationship services
//! - Automatic fallback chains with quality guarantees
//! - Performance-based routing decisions

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug, error, instrument};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::{
    errors::AppError,
    services::{
        hybrid_query_service::{HybridQuery, HybridQueryResult, HybridQueryType},
        ecs_graceful_degradation::{EcsGracefulDegradation, CircuitState},
    },
};

/// Query routing strategies based on system health and performance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryRoutingStrategy {
    /// Route to full ECS-enhanced hybrid queries (best quality)
    FullEcsEnhanced,
    /// Route to RAG-enhanced chronicle queries (medium quality)
    RagEnhanced,
    /// Route to basic chronicle-only queries (guaranteed fallback)
    ChronicleOnly,
    /// Route failed - all systems unavailable
    RoutingFailed,
}

/// Circuit breaker states for different service dependencies
#[derive(Debug, Clone)]
pub struct ServiceCircuitBreakers {
    /// ECS service circuit breaker
    pub ecs_circuit: CircuitBreakerState,
    /// RAG service circuit breaker
    pub rag_circuit: CircuitBreakerState,
    /// Relationship service circuit breaker
    pub relationship_circuit: CircuitBreakerState,
    /// Chronicle service circuit breaker (should rarely be open)
    pub chronicle_circuit: CircuitBreakerState,
}

/// Individual circuit breaker state
#[derive(Debug, Clone)]
pub struct CircuitBreakerState {
    /// Current state of the circuit breaker
    pub state: CircuitState,
    /// Failure count in current window
    pub failure_count: Arc<AtomicU64>,
    /// Success count in current window
    pub success_count: Arc<AtomicU64>,
    /// Last state change timestamp
    pub last_state_change: Arc<AtomicU64>,
    /// Configured failure threshold
    pub failure_threshold: u64,
    /// Recovery timeout (seconds)
    pub recovery_timeout_secs: u64,
}

impl Default for CircuitBreakerState {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: Arc::new(AtomicU64::new(0)),
            success_count: Arc::new(AtomicU64::new(0)),
            last_state_change: Arc::new(AtomicU64::new(0)),
            failure_threshold: 5,
            recovery_timeout_secs: 60,
        }
    }
}

impl Default for ServiceCircuitBreakers {
    fn default() -> Self {
        Self {
            ecs_circuit: CircuitBreakerState {
                failure_threshold: 3, // ECS is less tolerant
                recovery_timeout_secs: 30,
                ..Default::default()
            },
            rag_circuit: CircuitBreakerState {
                failure_threshold: 5, // RAG can tolerate more failures
                recovery_timeout_secs: 60,
                ..Default::default()
            },
            relationship_circuit: CircuitBreakerState {
                failure_threshold: 4,
                recovery_timeout_secs: 45,
                ..Default::default()
            },
            chronicle_circuit: CircuitBreakerState {
                failure_threshold: 10, // Chronicle should almost never fail
                recovery_timeout_secs: 120,
                ..Default::default()
            },
        }
    }
}

/// Query complexity analysis for routing decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryComplexity {
    /// Estimated computational complexity (0.0-1.0)
    pub complexity_score: f32,
    /// Whether query requires current ECS state
    pub requires_current_state: bool,
    /// Whether query requires relationship analysis
    pub requires_relationships: bool,
    /// Number of entities likely involved
    pub estimated_entity_count: usize,
    /// Expected data volume (small/medium/large)
    pub data_volume: DataVolume,
}

/// Expected data volume for query
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataVolume {
    Small,   // < 100 events/entities
    Medium,  // 100-1000 events/entities  
    Large,   // > 1000 events/entities
}

/// Query performance contract defining expected behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPerformanceContract {
    /// Maximum acceptable response time (ms)
    pub max_response_time_ms: u64,
    /// Minimum acceptable result quality (0.0-1.0)
    pub min_quality_score: f32,
    /// Whether fallback is acceptable
    pub allow_fallback: bool,
    /// Whether partial results are acceptable
    pub allow_partial_results: bool,
}

impl Default for QueryPerformanceContract {
    fn default() -> Self {
        Self {
            max_response_time_ms: 5000, // 5 seconds default
            min_quality_score: 0.7,
            allow_fallback: true,
            allow_partial_results: true,
        }
    }
}

/// Routing decision with rationale and fallback plan
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    /// Selected routing strategy
    pub strategy: QueryRoutingStrategy,
    /// Reasoning for the routing decision
    pub rationale: String,
    /// Fallback strategies in order of preference
    pub fallback_chain: Vec<QueryRoutingStrategy>,
    /// Expected performance characteristics
    pub performance_contract: QueryPerformanceContract,
}

/// Failure mode classification for specific error handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FailureMode {
    /// Service is completely unavailable
    ServiceUnavailable { service: String },
    /// Service is slow but functional
    ServiceDegraded { service: String, response_time_ms: u64 },
    /// Query is too complex for current system resources
    QueryTooComplex { complexity_score: f32 },
    /// Data inconsistency detected between services
    DataInconsistency { details: String },
    /// Resource exhaustion (memory, connections, etc.)
    ResourceExhaustion { resource: String },
    /// Authentication/authorization failure
    AuthorizationFailure { user_id: Uuid },
    /// Rate limiting triggered
    RateLimitExceeded { user_id: Uuid },
    /// Unknown system error
    UnknownError { error_context: String },
}

/// Routing metrics for monitoring and optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingMetrics {
    /// Total queries routed
    pub total_queries: u64,
    /// Queries routed by strategy
    pub strategy_counts: HashMap<String, u64>,
    /// Average response time by strategy (ms)
    pub avg_response_times: HashMap<String, f64>,
    /// Success rate by strategy (0.0-1.0)
    pub success_rates: HashMap<String, f64>,
    /// Circuit breaker state changes
    pub circuit_state_changes: u64,
    /// Fallback activations
    pub fallback_activations: u64,
}

impl Default for RoutingMetrics {
    fn default() -> Self {
        Self {
            total_queries: 0,
            strategy_counts: HashMap::new(),
            avg_response_times: HashMap::new(),
            success_rates: HashMap::new(),
            circuit_state_changes: 0,
            fallback_activations: 0,
        }
    }
}

/// Configuration for hybrid query routing
#[derive(Debug, Clone)]
pub struct HybridQueryRouterConfig {
    /// Enable intelligent routing (vs always using full ECS)
    pub enable_intelligent_routing: bool,
    /// Health check interval for services (seconds)
    pub health_check_interval_secs: u64,
    /// Performance monitoring window (seconds)
    pub performance_window_secs: u64,
    /// Circuit breaker configuration
    pub circuit_breaker_config: ServiceCircuitBreakers,
    /// Default performance contract
    pub default_performance_contract: QueryPerformanceContract,
}

impl Default for HybridQueryRouterConfig {
    fn default() -> Self {
        Self {
            enable_intelligent_routing: true,
            health_check_interval_secs: 30,
            performance_window_secs: 300, // 5 minutes
            circuit_breaker_config: ServiceCircuitBreakers::default(),
            default_performance_contract: QueryPerformanceContract::default(),
        }
    }
}

/// Hybrid Query Router - handles intelligent routing and failure contracts
pub struct HybridQueryRouter {
    /// Router configuration
    config: HybridQueryRouterConfig,
    /// Circuit breaker states for different services
    circuit_breakers: ServiceCircuitBreakers,
    /// Graceful degradation service for health monitoring
    degradation_service: Arc<EcsGracefulDegradation>,
    /// Current routing metrics
    metrics: Arc<std::sync::RwLock<RoutingMetrics>>,
    /// Last health check timestamp
    last_health_check: Arc<AtomicU64>,
}

impl HybridQueryRouter {
    /// Create a new hybrid query router
    pub fn new(
        config: HybridQueryRouterConfig,
        degradation_service: Arc<EcsGracefulDegradation>,
    ) -> Self {
        Self {
            circuit_breakers: config.circuit_breaker_config.clone(),
            config,
            degradation_service,
            metrics: Arc::new(std::sync::RwLock::new(RoutingMetrics::default())),
            last_health_check: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Make routing decision for a hybrid query
    #[instrument(skip(self), fields(user_id = %query.user_id))]
    pub async fn route_query(&self, query: &HybridQuery) -> Result<RoutingDecision, AppError> {
        debug!(
            query_type = ?query.query_type,
            user_id = %query.user_id,
            "Analyzing query for routing decision"
        );

        // Step 1: Update service health if needed
        self.update_service_health().await?;

        // Step 2: Analyze query complexity
        let complexity = self.analyze_query_complexity(query).await?;

        // Step 3: Check service availability
        let service_health = self.assess_service_health().await?;

        // Step 4: Make routing decision based on health and complexity
        let decision = self.make_routing_decision(&complexity, &service_health, query).await?;

        info!(
            query_type = ?query.query_type,
            user_id = %query.user_id,
            strategy = ?decision.strategy,
            rationale = %decision.rationale,
            "Query routing decision made"
        );

        // Step 5: Update metrics
        self.update_routing_metrics(&decision).await?;

        Ok(decision)
    }

    /// Update circuit breaker state based on operation result
    #[instrument(skip(self))]
    pub async fn record_operation_result(
        &self,
        service: &str,
        success: bool,
        response_time_ms: u64,
    ) -> Result<(), AppError> {
        let circuit = match service {
            "ecs" => &self.circuit_breakers.ecs_circuit,
            "rag" => &self.circuit_breakers.rag_circuit,
            "relationship" => &self.circuit_breakers.relationship_circuit,
            "chronicle" => &self.circuit_breakers.chronicle_circuit,
            _ => {
                warn!(service = service, "Unknown service for circuit breaker");
                return Ok(());
            }
        };

        if success {
            circuit.success_count.fetch_add(1, Ordering::Relaxed);
            
            // Check if we should close an open circuit
            if matches!(circuit.state, CircuitState::Open) {
                let now = chrono::Utc::now().timestamp() as u64;
                let last_change = circuit.last_state_change.load(Ordering::Relaxed);
                
                if now.saturating_sub(last_change) >= circuit.recovery_timeout_secs {
                    debug!(service = service, "Attempting to close circuit breaker");
                    // In real implementation, we'd update the state atomically
                }
            }
        } else {
            let failure_count = circuit.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
            
            // Check if we should open the circuit
            if failure_count >= circuit.failure_threshold && matches!(circuit.state, CircuitState::Closed) {
                warn!(
                    service = service,
                    failure_count = failure_count,
                    threshold = circuit.failure_threshold,
                    "Opening circuit breaker due to failures"
                );
                
                circuit.last_state_change.store(
                    chrono::Utc::now().timestamp() as u64,
                    Ordering::Relaxed
                );
                
                // Update metrics
                if let Ok(mut metrics) = self.metrics.write() {
                    metrics.circuit_state_changes += 1;
                }
            }
        }

        Ok(())
    }

    /// Get current routing metrics
    pub async fn get_routing_metrics(&self) -> Result<RoutingMetrics, AppError> {
        self.metrics
            .read()
            .map(|metrics| metrics.clone())
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to read routing metrics: {}", e)))
    }

    /// Classify failure mode for specific error handling
    pub fn classify_failure_mode(&self, error: &AppError, context: &str) -> FailureMode {
        match error {
            AppError::DatabaseQueryError(_) => FailureMode::ServiceUnavailable {
                service: "database".to_string(),
            },
            AppError::Unauthorized(_) => FailureMode::AuthorizationFailure {
                user_id: Uuid::nil(), // Would extract from context in real impl
            },
            AppError::ValidationError(_) => FailureMode::QueryTooComplex {
                complexity_score: 0.9, // Would calculate based on query
            },
            AppError::InternalServerErrorGeneric(msg) if msg.contains("timeout") => {
                FailureMode::ServiceDegraded {
                    service: context.to_string(),
                    response_time_ms: 10000, // Would extract from context
                }
            },
            _ => FailureMode::UnknownError {
                error_context: format!("{}: {}", context, error),
            },
        }
    }

    // Private helper methods

    /// Update service health by running health checks
    async fn update_service_health(&self) -> Result<(), AppError> {
        let now = chrono::Utc::now().timestamp() as u64;
        let last_check = self.last_health_check.load(Ordering::Relaxed);

        if now.saturating_sub(last_check) >= self.config.health_check_interval_secs {
            debug!("Running service health checks");
            
            // TODO: Implement actual health checks for each service
            // For now, we'll rely on the degradation service
            
            self.last_health_check.store(now, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Analyze query complexity for routing decisions
    async fn analyze_query_complexity(&self, query: &HybridQuery) -> Result<QueryComplexity, AppError> {
        let mut complexity_score = 0.3; // Base complexity
        let mut requires_current_state = query.include_current_state;
        let mut requires_relationships = query.include_relationships;
        let mut estimated_entity_count = 5; // Default estimate
        let mut data_volume = DataVolume::Small;

        // Analyze based on query type
        match &query.query_type {
            HybridQueryType::EntityTimeline { .. } => {
                complexity_score += 0.2;
                requires_current_state = true;
                estimated_entity_count = 1;
            },
            HybridQueryType::EventParticipants { .. } => {
                complexity_score += 0.3;
                requires_relationships = true;
                estimated_entity_count = 10;
                data_volume = DataVolume::Medium;
            },
            HybridQueryType::RelationshipHistory { .. } => {
                complexity_score += 0.4;
                requires_current_state = true;
                requires_relationships = true;
                estimated_entity_count = 2;
            },
            HybridQueryType::LocationQuery { include_recent_activity: true, .. } => {
                complexity_score += 0.5;
                requires_current_state = true;
                estimated_entity_count = 20;
                data_volume = DataVolume::Large;
            },
            HybridQueryType::LocationQuery { .. } => {
                complexity_score += 0.2;
                estimated_entity_count = 10;
            },
            HybridQueryType::NarrativeQuery { focus_entities: Some(entities), .. } => {
                complexity_score += 0.1 + (entities.len() as f32 * 0.05);
                estimated_entity_count = entities.len().max(1);
                if entities.len() > 10 {
                    data_volume = DataVolume::Large;
                }
            },
            HybridQueryType::NarrativeQuery { .. } => {
                complexity_score += 0.6; // Unknown scope - assume complex
                estimated_entity_count = 15;
                data_volume = DataVolume::Medium;
            },
        }

        // Adjust for max results
        if query.max_results > 100 {
            complexity_score += 0.1;
            data_volume = DataVolume::Large;
        }

        Ok(QueryComplexity {
            complexity_score: complexity_score.min(1.0),
            requires_current_state,
            requires_relationships,
            estimated_entity_count,
            data_volume,
        })
    }

    /// Assess current service health
    async fn assess_service_health(&self) -> Result<HashMap<String, f32>, AppError> {
        let mut health_scores = HashMap::new();

        // Check ECS health through degradation service
        let ecs_health = self.degradation_service.get_health_status().await;
        
        let ecs_score = if ecs_health.ecs_available && !ecs_health.fallback_mode_active {
            1.0 // Healthy
        } else if ecs_health.ecs_available {
            0.6 // Degraded (available but using fallback)
        } else {
            0.2 // Unhealthy
        };
        health_scores.insert("ecs".to_string(), ecs_score);

        // Check circuit breaker states
        health_scores.insert("rag".to_string(), self.circuit_health_score(&self.circuit_breakers.rag_circuit));
        health_scores.insert("relationship".to_string(), self.circuit_health_score(&self.circuit_breakers.relationship_circuit));
        health_scores.insert("chronicle".to_string(), self.circuit_health_score(&self.circuit_breakers.chronicle_circuit));

        Ok(health_scores)
    }

    /// Calculate health score from circuit breaker state
    fn circuit_health_score(&self, circuit: &CircuitBreakerState) -> f32 {
        match circuit.state {
            CircuitState::Closed => {
                let success = circuit.success_count.load(Ordering::Relaxed);
                let failures = circuit.failure_count.load(Ordering::Relaxed);
                let total = success + failures;
                
                if total == 0 {
                    1.0 // No data, assume healthy
                } else {
                    success as f32 / total as f32
                }
            },
            CircuitState::Open => 0.0,
            CircuitState::HalfOpen => 0.5,
        }
    }

    /// Make routing decision based on complexity and health
    async fn make_routing_decision(
        &self,
        complexity: &QueryComplexity,
        service_health: &HashMap<String, f32>,
        query: &HybridQuery,
    ) -> Result<RoutingDecision, AppError> {
        let ecs_health = service_health.get("ecs").unwrap_or(&0.0);
        let rag_health = service_health.get("rag").unwrap_or(&0.0);
        let chronicle_health = service_health.get("chronicle").unwrap_or(&1.0);

        // Build fallback chain
        let mut fallback_chain = vec![
            QueryRoutingStrategy::FullEcsEnhanced,
            QueryRoutingStrategy::RagEnhanced,
            QueryRoutingStrategy::ChronicleOnly,
        ];

        // Determine primary strategy
        let strategy = if !self.config.enable_intelligent_routing {
            QueryRoutingStrategy::FullEcsEnhanced
        } else if *ecs_health < 0.3 || (*rag_health < 0.3 && complexity.requires_current_state) {
            fallback_chain.remove(0); // Remove FullEcsEnhanced from fallbacks
            if *rag_health >= 0.5 && !complexity.requires_current_state {
                QueryRoutingStrategy::RagEnhanced
            } else if *chronicle_health >= 0.7 {
                fallback_chain.remove(0); // Remove RagEnhanced from fallbacks
                QueryRoutingStrategy::ChronicleOnly
            } else {
                QueryRoutingStrategy::RoutingFailed
            }
        } else if complexity.complexity_score > 0.8 && *ecs_health < 0.7 {
            // High complexity query but ECS not fully healthy
            fallback_chain.remove(0);
            QueryRoutingStrategy::RagEnhanced
        } else {
            QueryRoutingStrategy::FullEcsEnhanced
        };

        // Build rationale
        let rationale = match &strategy {
            QueryRoutingStrategy::FullEcsEnhanced => {
                format!("ECS healthy ({:.1}), query complexity {:.1}", ecs_health, complexity.complexity_score)
            },
            QueryRoutingStrategy::RagEnhanced => {
                format!("ECS degraded ({:.1}), using RAG fallback ({:.1})", ecs_health, rag_health)
            },
            QueryRoutingStrategy::ChronicleOnly => {
                format!("ECS/RAG unhealthy, chronicle-only fallback ({:.1})", chronicle_health)
            },
            QueryRoutingStrategy::RoutingFailed => {
                "All services unhealthy - routing failed".to_string()
            },
        };

        // Determine performance contract
        let performance_contract = QueryPerformanceContract {
            max_response_time_ms: match complexity.data_volume {
                DataVolume::Small => 2000,
                DataVolume::Medium => 5000,
                DataVolume::Large => 10000,
            },
            min_quality_score: match &strategy {
                QueryRoutingStrategy::FullEcsEnhanced => 0.9,
                QueryRoutingStrategy::RagEnhanced => 0.7,
                QueryRoutingStrategy::ChronicleOnly => 0.5,
                QueryRoutingStrategy::RoutingFailed => 0.0,
            },
            allow_fallback: matches!(strategy, 
                QueryRoutingStrategy::FullEcsEnhanced | QueryRoutingStrategy::RagEnhanced
            ),
            allow_partial_results: complexity.data_volume == DataVolume::Large,
        };

        Ok(RoutingDecision {
            strategy,
            rationale,
            fallback_chain,
            performance_contract,
        })
    }

    /// Update routing metrics
    async fn update_routing_metrics(&self, decision: &RoutingDecision) -> Result<(), AppError> {
        if let Ok(mut metrics) = self.metrics.write() {
            metrics.total_queries += 1;
            
            let strategy_name = format!("{:?}", decision.strategy);
            *metrics.strategy_counts.entry(strategy_name).or_insert(0) += 1;
        }

        Ok(())
    }
}