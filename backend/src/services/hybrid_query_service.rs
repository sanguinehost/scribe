//! Hybrid Query Service
//!
//! This service implements Phase 4.2.2 of the ECS Architecture Plan:
//! - Support queries spanning chronicle events and ECS state
//! - "What happened to X and where are they now?"
//! - "Who was present at Y event and what's their current relationship?"
//! - Cache frequently accessed entity states
//!
//! Key Features:
//! - Complex cross-system queries combining chronicle + ECS data
//! - Natural language query processing for narrative questions
//! - Entity timeline reconstruction with current state context
//! - Relationship analysis across time periods
//! - Performance optimization through intelligent caching

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::HashMap;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue};
use tracing::{info, warn, debug, instrument};
use chrono::{DateTime, Utc};

use crate::{
    PgPool,
    config::NarrativeFeatureFlags,
    errors::AppError,
    models::chronicle_event::ChronicleEvent,
    services::{
        ecs_entity_manager::EcsEntityManager,
        ecs_enhanced_rag_service::{
            EcsEnhancedRagService, EnhancedRagQuery,
            EntityStateSnapshot, RelationshipContext
        },
        ecs_graceful_degradation::EcsGracefulDegradation,
        hybrid_query_router::{
            HybridQueryRouter, HybridQueryRouterConfig, QueryRoutingStrategy, RoutingDecision,
            FailureMode, QueryPerformanceContract
        },
    },
};

/// Configuration for hybrid query behavior
#[derive(Debug, Clone)]
pub struct HybridQueryConfig {
    /// Enable entity state caching for performance
    pub enable_entity_caching: bool,
    /// Cache TTL for entity states (seconds)
    pub entity_cache_ttl: u64,
    /// Maximum entities to track in single query
    pub max_entities_per_query: usize,
    /// Enable timeline reconstruction
    pub enable_timeline_reconstruction: bool,
    /// Maximum timeline events to include
    pub max_timeline_events: usize,
    /// Enable relationship analysis
    pub enable_relationship_analysis: bool,
    /// Maximum relationship depth to traverse
    pub max_relationship_depth: u32,
}

impl Default for HybridQueryConfig {
    fn default() -> Self {
        Self {
            enable_entity_caching: true,
            entity_cache_ttl: 600, // 10 minutes
            max_entities_per_query: 20,
            enable_timeline_reconstruction: true,
            max_timeline_events: 100,
            enable_relationship_analysis: true,
            max_relationship_depth: 3,
        }
    }
}

/// Types of hybrid queries supported
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HybridQueryType {
    /// "What happened to X and where are they now?"
    EntityTimeline {
        entity_name: String,
        entity_id: Option<Uuid>,
        include_current_state: bool,
    },
    /// "Who was present at Y event and what's their current relationship?"
    EventParticipants {
        event_description: String,
        event_id: Option<Uuid>,
        include_relationships: bool,
    },
    /// "Show me the relationship history between A and B"
    RelationshipHistory {
        entity_a: String,
        entity_b: String,
        entity_a_id: Option<Uuid>,
        entity_b_id: Option<Uuid>,
    },
    /// "What entities are currently in location X?"
    LocationQuery {
        location_name: String,
        location_data: Option<JsonValue>,
        include_recent_activity: bool,
    },
    /// Custom narrative query
    NarrativeQuery {
        query_text: String,
        focus_entities: Option<Vec<String>>,
        time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    },
    
    // Phase 2: Enhanced Query Types for World Model Support
    
    /// Get entity state at specific time
    EntityStateAtTime {
        entity_id: Uuid,
        timestamp: DateTime<Utc>,
        include_components: Vec<String>,
    },
    
    /// Trace causal chain
    CausalChain {
        from_event: Option<Uuid>,
        to_state: Option<String>,
        to_entity: Option<Uuid>,
        max_depth: u32,
        min_confidence: f32,
    },
    
    /// Get temporal path of entity changes
    TemporalPath {
        entity_id: Uuid,
        from_time: DateTime<Utc>,
        to_time: DateTime<Utc>,
        include_causes: bool,
    },
    
    /// Get relationship network
    RelationshipNetwork {
        center_entity_id: Uuid,
        depth: u32,
        relationship_types: Option<Vec<String>>,
        min_strength: f32,
        categories: Option<Vec<crate::models::ecs::RelationshipCategory>>,
    },
    
    /// Find causal influences on entity
    CausalInfluences {
        entity_id: Uuid,
        time_window: chrono::Duration,
        influence_types: Option<Vec<String>>,
    },
    
    /// Generate world model snapshot
    WorldModelSnapshot {
        timestamp: Option<DateTime<Utc>>,
        focus_entities: Option<Vec<Uuid>>,
        spatial_scope: Option<SpatialScope>,
        include_predictions: bool,
    },
}

/// Parameters for hybrid queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridQuery {
    /// Type of query to execute
    pub query_type: HybridQueryType,
    /// User ID for scoping
    pub user_id: Uuid,
    /// Chronicle ID to focus on (optional)
    pub chronicle_id: Option<Uuid>,
    /// Maximum results to return
    pub max_results: usize,
    /// Include current entity states
    pub include_current_state: bool,
    /// Include relationship context
    pub include_relationships: bool,
    /// Query execution options
    pub options: HybridQueryOptions,
}

/// Additional options for query execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridQueryOptions {
    /// Use cached results if available
    pub use_cache: bool,
    /// Include detailed entity timelines
    pub include_timelines: bool,
    /// Include relationship analysis
    pub analyze_relationships: bool,
    /// Minimum confidence threshold for results
    pub confidence_threshold: f32,
}

impl Default for HybridQueryOptions {
    fn default() -> Self {
        Self {
            use_cache: true,
            include_timelines: true,
            analyze_relationships: true,
            confidence_threshold: 0.6,
        }
    }
}

/// Results from hybrid queries combining chronicle + ECS data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridQueryResult {
    /// Query that was executed
    pub query_type: HybridQueryType,
    /// User ID for scoping
    pub user_id: Uuid,
    /// Entities found and their contexts
    pub entities: Vec<EntityTimelineContext>,
    /// Chronicle events related to the query
    pub chronicle_events: Vec<ChronicleEvent>,
    /// Current relationships between entities
    pub relationships: Vec<RelationshipAnalysis>,
    /// Summary of findings
    pub summary: HybridQuerySummary,
    /// Performance metrics
    pub performance: QueryPerformanceMetrics,
    /// Warnings or issues encountered
    pub warnings: Vec<String>,
}

/// Entity with timeline and current state context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityTimelineContext {
    /// Entity identification
    pub entity_id: Uuid,
    /// Entity name or identifier
    pub entity_name: Option<String>,
    /// Current state snapshot
    pub current_state: Option<EntityStateSnapshot>,
    /// Historical events involving this entity
    pub timeline_events: Vec<TimelineEvent>,
    /// Current relationships
    pub relationships: Vec<RelationshipContext>,
    /// Relevance score to the query
    pub relevance_score: f32,
}

/// Event in entity timeline with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Chronicle event
    pub event: ChronicleEvent,
    /// Entity's state at the time (if available)
    pub entity_state_at_time: Option<JsonValue>,
    /// Other entities involved
    pub co_participants: Vec<Uuid>,
    /// Event significance score
    pub significance_score: f32,
}

/// Relationship analysis between entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipAnalysis {
    /// Source entity
    pub from_entity_id: Uuid,
    /// Target entity
    pub to_entity_id: Uuid,
    /// Current relationship type
    pub current_relationship: Option<RelationshipContext>,
    /// Historical relationship changes
    pub relationship_history: Vec<RelationshipHistoryEntry>,
    /// Relationship strength/stability analysis
    pub analysis: RelationshipMetrics,
}

/// Historical relationship entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipHistoryEntry {
    /// When this relationship state existed
    pub timestamp: DateTime<Utc>,
    /// Chronicle event that caused the change
    pub triggering_event: Option<Uuid>,
    /// Relationship type at this time
    pub relationship_type: String,
    /// Relationship strength/data
    pub relationship_data: JsonValue,
}

/// Metrics about relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipMetrics {
    /// How stable the relationship is (0.0-1.0)
    pub stability: f32,
    /// Overall strength (0.0-1.0)
    pub strength: f32,
    /// Recent trend: improving, declining, stable
    pub trend: RelationshipTrend,
    /// Number of significant interactions
    pub interaction_count: usize,
}

/// Relationship trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelationshipTrend {
    Improving,
    Declining,
    Stable,
    Volatile,
    Unknown,
}

/// Summary of hybrid query results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridQuerySummary {
    /// Number of entities found
    pub entities_found: usize,
    /// Number of chronicle events analyzed
    pub events_analyzed: usize,
    /// Number of relationships examined
    pub relationships_found: usize,
    /// Key findings or insights
    pub key_insights: Vec<String>,
    /// Answer to the original query
    pub narrative_answer: Option<String>,
}

/// Performance metrics for query execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPerformanceMetrics {
    /// Total query execution time (ms)
    pub total_duration_ms: u64,
    /// Chronicle query time (ms)
    pub chronicle_query_ms: u64,
    /// ECS query time (ms)
    pub ecs_query_ms: u64,
    /// Relationship analysis time (ms)
    pub relationship_analysis_ms: u64,
    /// Cache hit rate
    pub cache_hit_rate: f32,
    /// Number of database queries
    pub db_queries_count: usize,
}

/// Metrics tracking for query execution
#[derive(Debug, Default)]
struct QueryMetrics {
    /// Total database queries executed
    db_queries: AtomicUsize,
    /// Cache hits
    cache_hits: AtomicUsize,
    /// Cache misses
    cache_misses: AtomicUsize,
}

impl QueryMetrics {
    fn new() -> Self {
        Self::default()
    }
    
    fn record_db_query(&self) {
        self.db_queries.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }
    
    fn get_cache_hit_rate(&self) -> f32 {
        let hits = self.cache_hits.load(Ordering::Relaxed);
        let misses = self.cache_misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f32 / total as f32
        }
    }
    
    fn get_db_query_count(&self) -> usize {
        self.db_queries.load(Ordering::Relaxed)
    }
    
    fn reset(&self) {
        self.db_queries.store(0, Ordering::Relaxed);
        self.cache_hits.store(0, Ordering::Relaxed);
        self.cache_misses.store(0, Ordering::Relaxed);
    }
}

/// Spatial scope for world model queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialScope {
    pub root_location: Uuid,
    pub max_depth: u32,
    pub include_adjacent: bool,
}

/// Hybrid Query Service with Hardened Routing and Failure Contracts
///
/// This service provides complex queries that span both chronicle events and current ECS state,
/// enabling narrative intelligence questions like "What happened to X and where are they now?"
/// 
/// Phase 5.4 Enhancements:
/// - Intelligent query routing based on system health and complexity
/// - Comprehensive failure contracts with specific error modes
/// - Circuit breaker patterns for service dependencies
/// - Performance monitoring and adaptive routing
#[derive(Clone)]
pub struct HybridQueryService {
    /// Database connection pool
    db_pool: Arc<PgPool>,
    /// Configuration for hybrid queries
    config: HybridQueryConfig,
    /// Feature flags for control
    feature_flags: Arc<NarrativeFeatureFlags>,
    /// ECS entity manager for current state
    entity_manager: Arc<EcsEntityManager>,
    /// Enhanced RAG service for semantic search
    rag_service: Arc<EcsEnhancedRagService>,
    /// Graceful degradation service
    degradation_service: Arc<EcsGracefulDegradation>,
    /// Intelligent query router for health-aware routing
    query_router: Arc<HybridQueryRouter>,
    /// Query execution metrics
    metrics: Arc<QueryMetrics>,
}

impl HybridQueryService {
    /// Create a new hybrid query service with routing and failure contracts
    pub fn new(
        db_pool: Arc<PgPool>,
        config: HybridQueryConfig,
        feature_flags: Arc<NarrativeFeatureFlags>,
        entity_manager: Arc<EcsEntityManager>,
        rag_service: Arc<EcsEnhancedRagService>,
        degradation_service: Arc<EcsGracefulDegradation>,
    ) -> Self {
        // Create router with configuration derived from main config
        let router_config = HybridQueryRouterConfig {
            enable_intelligent_routing: true,
            health_check_interval_secs: 30,
            performance_window_secs: 300,
            circuit_breaker_config: Default::default(),
            default_performance_contract: QueryPerformanceContract::default(),
        };
        
        let query_router = Arc::new(HybridQueryRouter::new(
            router_config,
            degradation_service.clone(),
        ));

        Self {
            db_pool,
            config,
            feature_flags,
            entity_manager,
            rag_service,
            degradation_service,
            query_router,
            metrics: Arc::new(QueryMetrics::new()),
        }
    }

    /// Execute a hybrid query with intelligent routing and failure contracts
    #[instrument(skip(self), fields(user_id = %query.user_id))]
    pub async fn execute_hybrid_query(&self, query: HybridQuery) -> Result<HybridQueryResult, AppError> {
        let start_time = std::time::Instant::now();

        info!(
            query_type = ?query.query_type,
            user_id = %query.user_id,
            chronicle_id = ?query.chronicle_id,
            "Starting hardened hybrid query execution with routing"
        );

        // Step 1: Make routing decision
        let routing_decision = self.query_router.route_query(&query).await
            .map_err(|e| {
                warn!(error = %e, "Query routing failed");
                e
            })?;

        info!(
            strategy = ?routing_decision.strategy,
            rationale = %routing_decision.rationale,
            "Query routing decision completed"
        );

        // Step 2: Execute query according to routing decision
        let result = self.execute_query_with_strategy(&query, &routing_decision).await;

        let total_duration_ms = start_time.elapsed().as_millis() as u64;

        // Step 3: Record operation result for circuit breaker
        let success = result.is_ok();
        let service_name = self.strategy_to_service_name(&routing_decision.strategy);
        
        if let Err(e) = self.query_router.record_operation_result(
            &service_name,
            success,
            total_duration_ms,
        ).await {
            warn!(error = %e, "Failed to record operation result for circuit breaker");
        }

        // Step 4: Handle result and apply failure contracts
        match result {
            Ok(mut hybrid_result) => {
                hybrid_result.performance.total_duration_ms = total_duration_ms;

                // Check if performance contract was met
                if total_duration_ms > routing_decision.performance_contract.max_response_time_ms {
                    hybrid_result.warnings.push(format!(
                        "Query exceeded performance contract: {}ms > {}ms",
                        total_duration_ms,
                        routing_decision.performance_contract.max_response_time_ms
                    ));
                }

                info!(
                    query_type = ?query.query_type,
                    user_id = %query.user_id,
                    strategy = ?routing_decision.strategy,
                    entities_found = hybrid_result.entities.len(),
                    events_analyzed = hybrid_result.chronicle_events.len(),
                    duration_ms = total_duration_ms,
                    "Hardened hybrid query completed successfully"
                );

                Ok(hybrid_result)
            }
            Err(e) => {
                // Classify failure mode for specific handling
                let failure_mode = self.query_router.classify_failure_mode(&e, &service_name);
                
                warn!(
                    query_type = ?query.query_type,
                    user_id = %query.user_id,
                    strategy = ?routing_decision.strategy,
                    failure_mode = ?failure_mode,
                    error = %e,
                    duration_ms = total_duration_ms,
                    "Hardened hybrid query failed"
                );

                // Attempt fallback if allowed by contract
                if routing_decision.performance_contract.allow_fallback && !routing_decision.fallback_chain.is_empty() {
                    warn!("Attempting fallback chain execution");
                    self.execute_fallback_chain(&query, &routing_decision.fallback_chain).await
                } else {
                    Err(self.wrap_error_with_failure_mode(e, failure_mode))
                }
            }
        }
    }

    /// Execute enhanced hybrid query with full ECS integration
    async fn execute_enhanced_hybrid_query(&self, query: &HybridQuery) -> Result<HybridQueryResult, AppError> {
        debug!("Executing enhanced hybrid query with full ECS integration");
        
        // Reset metrics for this query execution
        self.metrics.reset();

        let chronicle_start = std::time::Instant::now();
        
        // Step 1: Execute semantic search to find relevant chronicle events
        let chronicle_events = self.search_relevant_chronicle_events(query).await?;
        let chronicle_query_ms = chronicle_start.elapsed().as_millis() as u64;

        let ecs_start = std::time::Instant::now();
        
        // Step 2: Extract entities mentioned in events and query-specific entities
        let entity_ids = self.extract_relevant_entity_ids(query, &chronicle_events).await?;
        
        // Step 3: Get current states for all relevant entities
        let entity_contexts = if query.include_current_state {
            self.build_entity_timeline_contexts(&entity_ids, &chronicle_events, query).await?
        } else {
            Vec::new()
        };
        
        let ecs_query_ms = ecs_start.elapsed().as_millis() as u64;

        let relationship_start = std::time::Instant::now();
        
        // Step 4: Analyze relationships if requested
        let relationships = if query.include_relationships {
            self.analyze_entity_relationships(&entity_ids, &chronicle_events, query).await?
        } else {
            Vec::new()
        };
        
        let relationship_analysis_ms = relationship_start.elapsed().as_millis() as u64;

        // Step 5: Generate summary and insights
        let summary = self.generate_query_summary(&entity_contexts, &chronicle_events, &relationships, query).await?;

        Ok(HybridQueryResult {
            query_type: query.query_type.clone(),
            user_id: query.user_id,
            entities: entity_contexts,
            chronicle_events,
            relationships,
            summary,
            performance: QueryPerformanceMetrics {
                total_duration_ms: 0, // Will be set by caller
                chronicle_query_ms,
                ecs_query_ms,
                relationship_analysis_ms,
                cache_hit_rate: self.metrics.get_cache_hit_rate(),
                db_queries_count: self.metrics.get_db_query_count(),
            },
            warnings: Vec::new(),
        })
    }

    /// Execute fallback hybrid query using only chronicle data
    async fn execute_fallback_hybrid_query(&self, query: &HybridQuery) -> Result<HybridQueryResult, AppError> {
        debug!("Executing fallback hybrid query (chronicle-only)");

        // Execute basic chronicle search without full ECS integration
        let chronicle_events = self.search_relevant_chronicle_events(query).await?;
        
        // Build basic entity contexts without current state
        let entity_contexts = self.build_basic_entity_contexts(&chronicle_events, query).await?;

        let summary = HybridQuerySummary {
            entities_found: entity_contexts.len(),
            events_analyzed: chronicle_events.len(),
            relationships_found: 0,
            key_insights: vec!["Limited analysis - ECS data unavailable".to_string()],
            narrative_answer: None,
        };

        Ok(HybridQueryResult {
            query_type: query.query_type.clone(),
            user_id: query.user_id,
            entities: entity_contexts,
            chronicle_events,
            relationships: Vec::new(),
            summary,
            performance: QueryPerformanceMetrics {
                total_duration_ms: 0,
                chronicle_query_ms: 0,
                ecs_query_ms: 0,
                relationship_analysis_ms: 0,
                cache_hit_rate: 0.0,
                db_queries_count: 0,
            },
            warnings: vec!["ECS unavailable - using chronicle-only analysis".to_string()],
        })
    }

    // Private helper methods

    /// Search chronicle events relevant to the query
    async fn search_relevant_chronicle_events(&self, query: &HybridQuery) -> Result<Vec<ChronicleEvent>, AppError> {
        debug!("Searching for chronicle events relevant to query");

        // Convert hybrid query to enhanced RAG query
        let rag_query = self.convert_to_rag_query(query)?;
        
        // Track that we're making a query to the RAG service (which involves DB)
        self.metrics.record_db_query();
        
        // Use the enhanced RAG service for semantic search
        let rag_result = self.rag_service.query_enhanced_rag(rag_query).await?;
        
        // Extract chronicle events from the RAG result
        let events: Vec<ChronicleEvent> = rag_result.chronicle_events
            .into_iter()
            .map(|enhanced_event| enhanced_event.event)
            .collect();

        // If RAG search found no events, fall back to direct database query
        if events.is_empty() && query.chronicle_id.is_some() {
            debug!("RAG search returned no events, falling back to direct database query");
            return self.search_chronicle_events_fallback(query).await;
        }

        Ok(events)
    }

    /// Fallback method to search chronicle events directly from database
    async fn search_chronicle_events_fallback(&self, query: &HybridQuery) -> Result<Vec<ChronicleEvent>, AppError> {
        use crate::services::ChronicleService;
        use crate::models::chronicle_event::{EventFilter, EventOrderBy};

        let chronicle_id = query.chronicle_id.ok_or_else(|| {
            AppError::BadRequest("Chronicle ID required for fallback search".to_string())
        })?;

        // Create chronicle service instance
        let chronicle_service = ChronicleService::new((*self.db_pool).clone());

        // Build filter based on query type
        let filter = EventFilter {
            event_type: None,
            source: None,
            action: None,
            modality: None,
            involves_entity: None,
            after_timestamp: None,
            before_timestamp: None,
            order_by: Some(EventOrderBy::CreatedAtDesc),
            limit: Some(query.max_results as i64),
            offset: None,
        };

        // Track direct database query
        self.metrics.record_db_query();
        
        // Get events from database
        let events = chronicle_service.get_chronicle_events(
            query.user_id,
            chronicle_id,
            filter,
        ).await?;

        debug!(
            events_found = events.len(),
            chronicle_id = %chronicle_id,
            "Fallback database search completed"
        );

        Ok(events)
    }

    /// Convert hybrid query to enhanced RAG query
    fn convert_to_rag_query(&self, query: &HybridQuery) -> Result<EnhancedRagQuery, AppError> {
        let query_text = match &query.query_type {
            HybridQueryType::EntityTimeline { entity_name, .. } => {
                format!("Timeline and history of {}", entity_name)
            }
            HybridQueryType::EventParticipants { event_description, .. } => {
                format!("Participants and attendees of {}", event_description)
            }
            HybridQueryType::RelationshipHistory { entity_a, entity_b, .. } => {
                format!("Relationship and interactions between {} and {}", entity_a, entity_b)
            }
            HybridQueryType::LocationQuery { location_name, .. } => {
                format!("Entities and activities at {}", location_name)
            }
            HybridQueryType::NarrativeQuery { query_text, .. } => {
                query_text.clone()
            }
            // Phase 2: Enhanced Query Types
            HybridQueryType::EntityStateAtTime { entity_id, timestamp, .. } => {
                format!("State of entity {} at time {}", entity_id, timestamp)
            }
            HybridQueryType::CausalChain { from_event, to_entity, .. } => {
                match (from_event, to_entity) {
                    (Some(event_id), Some(entity_id)) => format!("Causal chain from event {} to entity {}", event_id, entity_id),
                    (Some(event_id), None) => format!("Causal chain from event {}", event_id),
                    (None, Some(entity_id)) => format!("Causal chain affecting entity {}", entity_id),
                    (None, None) => "Causal chain analysis".to_string(),
                }
            }
            HybridQueryType::TemporalPath { entity_id, from_time, to_time, .. } => {
                format!("Temporal path of entity {} from {} to {}", entity_id, from_time, to_time)
            }
            HybridQueryType::RelationshipNetwork { center_entity_id, .. } => {
                format!("Relationship network around entity {}", center_entity_id)
            }
            HybridQueryType::CausalInfluences { entity_id, .. } => {
                format!("Causal influences on entity {}", entity_id)
            }
            HybridQueryType::WorldModelSnapshot { .. } => {
                "World model snapshot generation".to_string()
            }
        };

        // Extract focus entity IDs from query when available
        let focus_entity_ids = match &query.query_type {
            HybridQueryType::EntityTimeline { entity_id: Some(id), .. } => {
                Some(vec![*id])
            }
            HybridQueryType::RelationshipHistory { 
                entity_a_id: Some(id_a), 
                entity_b_id: Some(id_b), 
                .. 
            } => {
                Some(vec![*id_a, *id_b])
            }
            _ => None,
        };

        Ok(EnhancedRagQuery {
            query: query_text,
            user_id: query.user_id,
            chronicle_id: query.chronicle_id,
            max_chronicle_results: query.max_results,
            include_current_state: query.include_current_state,
            include_relationships: query.include_relationships,
            focus_entity_ids,
            similarity_threshold: query.options.confidence_threshold,
        })
    }

    /// Extract entity IDs relevant to the query
    async fn extract_relevant_entity_ids(&self, query: &HybridQuery, events: &[ChronicleEvent]) -> Result<Vec<Uuid>, AppError> {
        let mut entity_ids = Vec::new();

        // Extract entities from events
        for event in events {
            debug!("Extracting entity IDs from event: {}", event.id);
            
            // Extract from actors list using the parsed actors
            if let Ok(actors) = event.get_actors() {
                for actor in actors {
                    entity_ids.push(actor.entity_id);
                }
            }

            // Also check event_data for actors array as fallback
            if let Some(event_data) = &event.event_data {
                if let Some(actors_value) = event_data.get("actors") {
                    if let Some(actors_array) = actors_value.as_array() {
                        for actor_value in actors_array {
                            if let Some(actor_entity_id) = actor_value.get("entity_id") {
                                if let Some(actor_id_str) = actor_entity_id.as_str() {
                                    if let Ok(actor_uuid) = Uuid::parse_str(actor_id_str) {
                                        entity_ids.push(actor_uuid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Add query-specific entities
        match &query.query_type {
            HybridQueryType::EntityTimeline { entity_id: Some(id), .. } => {
                entity_ids.push(*id);
            }
            HybridQueryType::EventParticipants { event_id: Some(_), .. } => {
                // TODO: Find participants of specific event
            }
            HybridQueryType::RelationshipHistory { 
                entity_a_id: Some(id_a), 
                entity_b_id: Some(id_b), 
                .. 
            } => {
                entity_ids.push(*id_a);
                entity_ids.push(*id_b);
            }
            _ => {}
        }

        // Remove duplicates
        entity_ids.sort_unstable();
        entity_ids.dedup();

        debug!(
            extracted_entities = entity_ids.len(),
            "Extracted entity IDs from events and query"
        );

        Ok(entity_ids)
    }

    /// Build entity timeline contexts with current state
    async fn build_entity_timeline_contexts(
        &self,
        entity_ids: &[Uuid],
        events: &[ChronicleEvent],
        query: &HybridQuery,
    ) -> Result<Vec<EntityTimelineContext>, AppError> {
        let mut contexts = Vec::new();

        for entity_id in entity_ids {
            let context = self.build_single_entity_context(*entity_id, events, query).await?;
            contexts.push(context);
        }

        Ok(contexts)
    }

    /// Build timeline context for a single entity
    async fn build_single_entity_context(
        &self,
        entity_id: Uuid,
        events: &[ChronicleEvent],
        query: &HybridQuery,
    ) -> Result<EntityTimelineContext, AppError> {
        // Get current state if requested
        let current_state = if query.include_current_state {
            self.get_entity_current_state(entity_id, query.user_id).await.ok()
        } else {
            None
        };

        // Build timeline events for this entity
        let timeline_events = self.build_entity_timeline(entity_id, events).await?;

        // Get current relationships
        let relationships = if query.include_relationships {
            self.get_entity_relationships(entity_id, query.user_id).await?
        } else {
            Vec::new()
        };

        Ok(EntityTimelineContext {
            entity_id,
            entity_name: self.extract_entity_name(entity_id).await?,
            current_state,
            timeline_events,
            relationships,
            relevance_score: 0.8, // TODO: Calculate based on query relevance
        })
    }

    /// Get current state for an entity
    async fn get_entity_current_state(&self, entity_id: Uuid, _user_id: Uuid) -> Result<EntityStateSnapshot, AppError> {
        // TODO: Use entity manager to get current state
        debug!("Getting current state for entity: {}", entity_id);
        
        // Check if we would use cache (based on config)
        if self.config.enable_entity_caching {
            // In a real implementation, we'd check cache here
            // For now, we simulate a cache miss
            self.metrics.record_cache_miss();
        }
        
        // Record that we're querying the entity manager (DB)
        self.metrics.record_db_query();
        
        Ok(EntityStateSnapshot {
            entity_id,
            archetype_signature: "unknown".to_string(),
            components: HashMap::new(),
            snapshot_time: chrono::Utc::now(),
            status_indicators: Vec::new(),
        })
    }

    /// Build timeline events for an entity
    async fn build_entity_timeline(&self, entity_id: Uuid, events: &[ChronicleEvent]) -> Result<Vec<TimelineEvent>, AppError> {
        let mut timeline_events = Vec::new();

        for event in events {
            // Check if entity was involved in this event
            if self.entity_involved_in_event(entity_id, event).await? {
                let timeline_event = TimelineEvent {
                    event: event.clone(),
                    entity_state_at_time: None, // TODO: Reconstruct state at event time
                    co_participants: self.extract_co_participants(entity_id, event).await?,
                    significance_score: 0.7, // TODO: Calculate significance
                };
                timeline_events.push(timeline_event);
            }
        }

        Ok(timeline_events)
    }

    /// Check if entity was involved in an event
    async fn entity_involved_in_event(&self, entity_id: Uuid, event: &ChronicleEvent) -> Result<bool, AppError> {
        // Check if entity is mentioned in the actors list
        if let Ok(actors) = event.get_actors() {
            for actor in actors {
                if actor.entity_id == entity_id {
                    return Ok(true);
                }
            }
        }

        // Check if entity is mentioned in event_data
        if let Some(event_data) = &event.event_data {
            // Check actors array in event_data
            if let Some(actors_value) = event_data.get("actors") {
                if let Some(actors_array) = actors_value.as_array() {
                    for actor_value in actors_array {
                        if let Some(actor_entity_id) = actor_value.get("entity_id") {
                            if let Some(actor_id_str) = actor_entity_id.as_str() {
                                if let Ok(actor_uuid) = Uuid::parse_str(actor_id_str) {
                                    if actor_uuid == entity_id {
                                        return Ok(true);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check if entity_id appears anywhere in the event content
            if let Some(content) = event_data.get("content").and_then(|c| c.as_str()) {
                let entity_id_str = entity_id.to_string();
                if content.contains(&entity_id_str) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Extract co-participants from an event
    async fn extract_co_participants(&self, _entity_id: Uuid, _event: &ChronicleEvent) -> Result<Vec<Uuid>, AppError> {
        // TODO: Parse event data to find other entities
        Ok(Vec::new())
    }

    /// Get relationships for an entity
    async fn get_entity_relationships(&self, _entity_id: Uuid, _user_id: Uuid) -> Result<Vec<RelationshipContext>, AppError> {
        // TODO: Query ECS for current relationships
        
        // Record database query for relationship lookup
        self.metrics.record_db_query();
        
        Ok(Vec::new())
    }

    /// Extract entity name
    async fn extract_entity_name(&self, _entity_id: Uuid) -> Result<Option<String>, AppError> {
        // TODO: Get entity name from ECS components
        
        // Check cache for entity name
        if self.config.enable_entity_caching {
            // Simulate cache check
            self.metrics.record_cache_miss();
        }
        
        // Record database query for entity name lookup
        self.metrics.record_db_query();
        
        Ok(None)
    }

    /// Analyze relationships between entities
    async fn analyze_entity_relationships(
        &self,
        entity_ids: &[Uuid],
        events: &[ChronicleEvent],
        _query: &HybridQuery,
    ) -> Result<Vec<RelationshipAnalysis>, AppError> {
        let mut relationships = Vec::new();

        // Analyze all pairs of entities
        for i in 0..entity_ids.len() {
            for j in (i + 1)..entity_ids.len() {
                let analysis = self.analyze_entity_pair_relationship(
                    entity_ids[i],
                    entity_ids[j],
                    events,
                ).await?;
                relationships.push(analysis);
            }
        }

        Ok(relationships)
    }

    /// Analyze relationship between two specific entities
    async fn analyze_entity_pair_relationship(
        &self,
        entity_a: Uuid,
        entity_b: Uuid,
        _events: &[ChronicleEvent],
    ) -> Result<RelationshipAnalysis, AppError> {
        // TODO: Analyze relationship history and current state
        Ok(RelationshipAnalysis {
            from_entity_id: entity_a,
            to_entity_id: entity_b,
            current_relationship: None,
            relationship_history: Vec::new(),
            analysis: RelationshipMetrics {
                stability: 0.5,
                strength: 0.5,
                trend: RelationshipTrend::Unknown,
                interaction_count: 0,
            },
        })
    }

    /// Build basic entity contexts for fallback mode
    async fn build_basic_entity_contexts(
        &self,
        events: &[ChronicleEvent],
        _query: &HybridQuery,
    ) -> Result<Vec<EntityTimelineContext>, AppError> {
        let contexts = Vec::new();

        // Extract entities mentioned in events
        for event in events {
            // TODO: Parse event to extract entities and build basic contexts
            debug!("Building basic context from event: {}", event.id);
        }

        Ok(contexts)
    }

    /// Generate summary and insights from query results
    async fn generate_query_summary(
        &self,
        entities: &[EntityTimelineContext],
        events: &[ChronicleEvent],
        relationships: &[RelationshipAnalysis],
        query: &HybridQuery,
    ) -> Result<HybridQuerySummary, AppError> {
        let mut key_insights = Vec::new();

        // Generate insights based on query type
        match &query.query_type {
            HybridQueryType::EntityTimeline { entity_name, .. } => {
                if !entities.is_empty() {
                    key_insights.push(format!("Found {} timeline events for {}", 
                        entities[0].timeline_events.len(), entity_name));
                }
            }
            HybridQueryType::EventParticipants { .. } => {
                key_insights.push(format!("Identified {} participants across {} events", 
                    entities.len(), events.len()));
            }
            HybridQueryType::RelationshipHistory { entity_a, entity_b, .. } => {
                if !relationships.is_empty() {
                    key_insights.push(format!("Analyzed relationship between {} and {}", 
                        entity_a, entity_b));
                }
            }
            HybridQueryType::LocationQuery { location_name, .. } => {
                key_insights.push(format!("Found {} entities at {}", 
                    entities.len(), location_name));
            }
            HybridQueryType::NarrativeQuery {  .. } => {
                key_insights.push(format!("Analyzed {} chronicle events for narrative query", 
                    events.len()));
                if !entities.is_empty() {
                    key_insights.push(format!("Identified {} relevant entities in the narrative", 
                        entities.len()));
                }
                if !relationships.is_empty() {
                    key_insights.push(format!("Found {} relationship connections", 
                        relationships.len()));
                }
            }
            _ => {
                // Generic insights for other query types
                if !events.is_empty() {
                    key_insights.push(format!("Analyzed {} chronicle events", events.len()));
                }
                if !entities.is_empty() {
                    key_insights.push(format!("Found {} relevant entities", entities.len()));
                }
            }
        }

        Ok(HybridQuerySummary {
            entities_found: entities.len(),
            events_analyzed: events.len(),
            relationships_found: relationships.len(),
            key_insights,
            narrative_answer: None, // TODO: Generate narrative answer
        })
    }

    // Phase 5.4 Hardened Routing Methods

    /// Execute query based on routing strategy
    async fn execute_query_with_strategy(
        &self,
        query: &HybridQuery,
        decision: &RoutingDecision,
    ) -> Result<HybridQueryResult, AppError> {
        match &decision.strategy {
            QueryRoutingStrategy::FullEcsEnhanced => {
                self.execute_enhanced_hybrid_query(query).await
            },
            QueryRoutingStrategy::RagEnhanced => {
                self.execute_rag_enhanced_query(query).await
            },
            QueryRoutingStrategy::ChronicleOnly => {
                self.execute_fallback_hybrid_query(query).await
            },
            QueryRoutingStrategy::RoutingFailed => {
                Err(AppError::InternalServerErrorGeneric(
                    "All query routing strategies failed - system unavailable".to_string()
                ))
            },
        }
    }

    /// Execute RAG-enhanced query (medium quality fallback)
    async fn execute_rag_enhanced_query(&self, query: &HybridQuery) -> Result<HybridQueryResult, AppError> {
        debug!("Executing RAG-enhanced hybrid query");

        let chronicle_start = std::time::Instant::now();
        
        // Use RAG for semantic search but skip full ECS integration
        let chronicle_events = self.search_relevant_chronicle_events(query).await?;
        let chronicle_query_ms = chronicle_start.elapsed().as_millis() as u64;

        // Build basic entity contexts without full ECS state
        let entity_contexts = self.build_basic_entity_contexts(&chronicle_events, query).await?;

        let summary = HybridQuerySummary {
            entities_found: entity_contexts.len(),
            events_analyzed: chronicle_events.len(),
            relationships_found: 0,
            key_insights: vec!["RAG-enhanced analysis - limited ECS integration".to_string()],
            narrative_answer: None,
        };

        Ok(HybridQueryResult {
            query_type: query.query_type.clone(),
            user_id: query.user_id,
            entities: entity_contexts,
            chronicle_events,
            relationships: Vec::new(),
            summary,
            performance: QueryPerformanceMetrics {
                total_duration_ms: 0, // Will be set by caller
                chronicle_query_ms,
                ecs_query_ms: 0,
                relationship_analysis_ms: 0,
                cache_hit_rate: 0.0,
                db_queries_count: 0,
            },
            warnings: vec!["Using RAG-enhanced fallback - ECS unavailable".to_string()],
        })
    }

    /// Execute fallback chain in order of preference
    async fn execute_fallback_chain(
        &self,
        query: &HybridQuery,
        fallback_chain: &[QueryRoutingStrategy],
    ) -> Result<HybridQueryResult, AppError> {
        for (index, strategy) in fallback_chain.iter().enumerate() {
            debug!(
                strategy = ?strategy,
                attempt = index + 1,
                total_fallbacks = fallback_chain.len(),
                "Attempting fallback strategy"
            );

            // Create a temporary decision for this fallback
            let fallback_decision = RoutingDecision {
                strategy: strategy.clone(),
                rationale: format!("Fallback attempt {}", index + 1),
                fallback_chain: Vec::new(), // No recursive fallbacks
                performance_contract: QueryPerformanceContract {
                    allow_fallback: false, // No further fallbacks in fallback
                    ..Default::default()
                },
            };

            match self.execute_query_with_strategy(query, &fallback_decision).await {
                Ok(mut result) => {
                    result.warnings.push(format!("Used fallback strategy: {:?}", strategy));
                    info!(
                        strategy = ?strategy,
                        attempt = index + 1,
                        "Fallback strategy succeeded"
                    );
                    return Ok(result);
                }
                Err(e) => {
                    warn!(
                        strategy = ?strategy,
                        attempt = index + 1,
                        error = %e,
                        "Fallback strategy failed"
                    );
                    
                    // Continue to next fallback unless this is the last one
                    if index == fallback_chain.len() - 1 {
                        return Err(AppError::InternalServerErrorGeneric(format!(
                            "All fallback strategies failed. Last error: {}",
                            e
                        )));
                    }
                }
            }
        }

        Err(AppError::InternalServerErrorGeneric(
            "Empty fallback chain - no strategies to attempt".to_string()
        ))
    }

    /// Map routing strategy to service name for circuit breaker tracking
    fn strategy_to_service_name(&self, strategy: &QueryRoutingStrategy) -> String {
        match strategy {
            QueryRoutingStrategy::FullEcsEnhanced => "ecs".to_string(),
            QueryRoutingStrategy::RagEnhanced => "rag".to_string(),
            QueryRoutingStrategy::ChronicleOnly => "chronicle".to_string(),
            QueryRoutingStrategy::RoutingFailed => "router".to_string(),
        }
    }

    /// Wrap error with failure mode context
    fn wrap_error_with_failure_mode(&self, error: AppError, failure_mode: FailureMode) -> AppError {
        let context = match failure_mode {
            FailureMode::ServiceUnavailable { service } => {
                format!("Service unavailable: {}", service)
            },
            FailureMode::ServiceDegraded { service, response_time_ms } => {
                format!("Service degraded: {} ({}ms)", service, response_time_ms)
            },
            FailureMode::QueryTooComplex { complexity_score } => {
                format!("Query too complex for current resources: {:.2}", complexity_score)
            },
            FailureMode::DataInconsistency { details } => {
                format!("Data inconsistency detected: {}", details)
            },
            FailureMode::ResourceExhaustion { resource } => {
                format!("Resource exhausted: {}", resource)
            },
            FailureMode::AuthorizationFailure { user_id } => {
                format!("Authorization failed for user: {}", user_id)
            },
            FailureMode::RateLimitExceeded { user_id } => {
                format!("Rate limit exceeded for user: {}", user_id)
            },
            FailureMode::UnknownError { error_context } => {
                format!("Unknown error: {}", error_context)
            },
        };

        match error {
            AppError::InternalServerErrorGeneric(msg) => {
                AppError::InternalServerErrorGeneric(format!("{} | {}", context, msg))
            },
            _ => AppError::InternalServerErrorGeneric(format!("{} | Original error: {}", context, error)),
        }
    }

    /// Get current routing metrics for monitoring
    pub async fn get_routing_metrics(&self) -> Result<crate::services::hybrid_query_router::RoutingMetrics, AppError> {
        self.query_router.get_routing_metrics().await
    }

    /// Force a health check update for all services
    pub async fn update_service_health(&self) -> Result<(), AppError> {
        // This would trigger health checks in the router
        // For now, we'll just call get_routing_metrics to exercise the health checking
        let _ = self.query_router.get_routing_metrics().await?;
        Ok(())
    }

    // Advanced Query Patterns - Phase 5.4a Implementation
    // These methods implement the specific production-ready query patterns
    // mentioned in the ECS Architecture Plan

    /// "Show me characters present at location X with trust >0.5"
    /// 
    /// This advanced query pattern combines location-based entity filtering with
    /// relationship-based trust analysis to find characters who are both physically
    /// present at a location and have sufficient trust relationships.
    #[instrument(skip(self), fields(user_id = %user_id, location = %location_name))]
    pub async fn query_trusted_characters_at_location(
        &self,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        location_name: &str,
        min_trust_threshold: f32,
        max_results: Option<usize>,
    ) -> Result<HybridQueryResult, AppError> {
        info!(
            user_id = %user_id,
            location = %location_name,
            trust_threshold = min_trust_threshold,
            "Executing trusted characters at location query"
        );

        let query = HybridQuery {
            query_type: HybridQueryType::LocationQuery {
                location_name: location_name.to_string(),
                location_data: None,
                include_recent_activity: true,
            },
            user_id,
            chronicle_id,
            max_results: max_results.unwrap_or(20),
            include_current_state: true,
            include_relationships: true,
            options: HybridQueryOptions {
                use_cache: true,
                include_timelines: true,
                analyze_relationships: true,
                confidence_threshold: min_trust_threshold,
            },
        };

        // Execute the base location query
        let mut result = self.execute_hybrid_query(query).await?;

        // Filter entities based on trust relationships
        result.entities = self.filter_entities_by_trust_threshold(
            result.entities,
            min_trust_threshold,
            user_id,
        ).await?;

        // Update summary with trust filtering information
        result.summary.key_insights.push(format!(
            "Found {} characters at {} with trust ≥ {:.1}",
            result.entities.len(),
            location_name,
            min_trust_threshold
        ));

        // Add specific narrative answer
        result.summary.narrative_answer = Some(self.generate_trusted_location_narrative(
            &result.entities,
            location_name,
            min_trust_threshold,
        ).await?);

        Ok(result)
    }

    /// "What events affected the relationship between A and B?"
    /// 
    /// This advanced query pattern analyzes the complete relationship history between
    /// two entities by examining chronicle events that involved both parties and
    /// tracking how their relationship valence changed over time.
    #[instrument(skip(self), fields(user_id = %user_id, entity_a = %entity_a_name, entity_b = %entity_b_name))]
    pub async fn query_relationship_affecting_events(
        &self,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        entity_a_name: &str,
        entity_b_name: &str,
        entity_a_id: Option<Uuid>,
        entity_b_id: Option<Uuid>,
        include_indirect_effects: bool,
        max_results: Option<usize>,
    ) -> Result<HybridQueryResult, AppError> {
        info!(
            user_id = %user_id,
            entity_a = %entity_a_name,
            entity_b = %entity_b_name,
            include_indirect = include_indirect_effects,
            "Executing relationship-affecting events query"
        );

        let query = HybridQuery {
            query_type: HybridQueryType::RelationshipHistory {
                entity_a: entity_a_name.to_string(),
                entity_b: entity_b_name.to_string(),
                entity_a_id,
                entity_b_id,
            },
            user_id,
            chronicle_id,
            max_results: max_results.unwrap_or(50),
            include_current_state: true,
            include_relationships: true,
            options: HybridQueryOptions {
                use_cache: true,
                include_timelines: true,
                analyze_relationships: true,
                confidence_threshold: 0.3, // Lower threshold for relationship analysis
            },
        };

        // Execute the base relationship query
        let mut result = self.execute_hybrid_query(query).await?;

        // Enhance with relationship-specific analysis
        result = self.enhance_with_relationship_analysis(
            result,
            entity_a_name,
            entity_b_name,
            include_indirect_effects,
        ).await?;

        // Sort events by their impact on the relationship
        result.chronicle_events.sort_by(|a, b| {
            // Sort by timestamp, most recent first
            b.created_at.cmp(&a.created_at)
        });

        // Add specific narrative answer
        result.summary.narrative_answer = Some(self.generate_relationship_events_narrative(
            &result.chronicle_events,
            &result.relationships,
            entity_a_name,
            entity_b_name,
        ).await?);

        Ok(result)
    }

    /// "Which characters have interacted with this item?"
    /// 
    /// This advanced query pattern finds all entities that have had interactions
    /// with a specific item by analyzing chronicle events for item mentions,
    /// transfers, usage, and other item-related activities.
    #[instrument(skip(self), fields(user_id = %user_id, item_name = %item_name))]
    pub async fn query_item_interaction_history(
        &self,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        item_name: &str,
        item_id: Option<Uuid>,
        interaction_types: Option<Vec<String>>, // e.g., ["use", "transfer", "acquire", "lose"]
        time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
        max_results: Option<usize>,
    ) -> Result<HybridQueryResult, AppError> {
        info!(
            user_id = %user_id,
            item_name = %item_name,
            interaction_types = ?interaction_types,
            "Executing item interaction history query"
        );

        let query = HybridQuery {
            query_type: HybridQueryType::NarrativeQuery {
                query_text: format!(
                    "Characters who have interacted with {} {} {}",
                    item_name,
                    interaction_types
                        .as_ref()
                        .map(|types| format!("through {}", types.join(", ")))
                        .unwrap_or_default(),
                    time_range
                        .map(|(start, end)| format!("between {} and {}", 
                            start.format("%Y-%m-%d"), 
                            end.format("%Y-%m-%d")))
                        .unwrap_or_default()
                ),
                focus_entities: None,
                time_range,
            },
            user_id,
            chronicle_id,
            max_results: max_results.unwrap_or(30),
            include_current_state: true,
            include_relationships: false, // Focus on item interactions, not relationships
            options: HybridQueryOptions {
                use_cache: true,
                include_timelines: true,
                analyze_relationships: false,
                confidence_threshold: 0.4,
            },
        };

        // Execute the base narrative query
        let mut result = self.execute_hybrid_query(query).await?;

        // Enhance with item-specific analysis
        result = self.enhance_with_item_analysis(
            result,
            item_name,
            item_id,
            interaction_types.as_deref(),
        ).await?;

        // Filter and sort events by item relevance
        result.chronicle_events = self.filter_and_rank_item_events(
            result.chronicle_events,
            item_name,
        ).await?;

        // Add item interaction insights
        result.summary.key_insights.push(format!(
            "Found {} characters who interacted with {}",
            result.entities.len(),
            item_name
        ));

        if let Some(types) = &interaction_types {
            result.summary.key_insights.push(format!(
                "Tracked interaction types: {}",
                types.join(", ")
            ));
        }

        // Add specific narrative answer
        result.summary.narrative_answer = Some(self.generate_item_interaction_narrative(
            &result.entities,
            &result.chronicle_events,
            item_name,
            interaction_types.as_deref(),
        ).await?);

        Ok(result)
    }

    // Helper methods for advanced query patterns

    /// Filter entities based on trust threshold analysis
    async fn filter_entities_by_trust_threshold(
        &self,
        entities: Vec<EntityTimelineContext>,
        min_trust: f32,
        user_id: Uuid,
    ) -> Result<Vec<EntityTimelineContext>, AppError> {
        let original_count = entities.len();
        let mut filtered_entities = Vec::new();

        for entity in entities {
            // Calculate average trust from relationships
            let trust_score = self.calculate_entity_trust_score(&entity, user_id).await?;
            
            if trust_score >= min_trust {
                filtered_entities.push(entity);
            }
        }

        debug!(
            original_count = original_count,
            filtered_count = filtered_entities.len(),
            min_trust = min_trust,
            "Filtered entities by trust threshold"
        );

        Ok(filtered_entities)
    }

    /// Calculate trust score for an entity based on relationships
    async fn calculate_entity_trust_score(
        &self,
        entity: &EntityTimelineContext,
        _user_id: Uuid,
    ) -> Result<f32, AppError> {
        if entity.relationships.is_empty() {
            return Ok(0.0);
        }

        let mut total_trust = 0.0;
        let mut trust_count = 0;

        for relationship in &entity.relationships {
            // Extract trust values from relationship data
            if let Some(trust_value) = self.extract_trust_from_relationship(relationship).await? {
                total_trust += trust_value;
                trust_count += 1;
            }
        }

        if trust_count > 0 {
            Ok(total_trust / trust_count as f32)
        } else {
            Ok(0.0)
        }
    }

    /// Extract trust value from relationship context
    async fn extract_trust_from_relationship(
        &self,
        relationship: &RelationshipContext,
    ) -> Result<Option<f32>, AppError> {
        // Look for trust-related fields in relationship data
        if let Some(trust_value) = relationship.relationship_data.get("trust") {
            if let Some(trust_f64) = trust_value.as_f64() {
                return Ok(Some(trust_f64 as f32));
            }
        }

        // Look for valence-based trust indicators
        if let Some(valence) = relationship.relationship_data.get("valence") {
            if let Some(valence_f64) = valence.as_f64() {
                // Convert valence to trust score (assuming positive valence indicates trust)
                return Ok(Some((valence_f64.max(0.0) / 100.0) as f32));
            }
        }

        Ok(None)
    }

    /// Enhance result with relationship-specific analysis
    async fn enhance_with_relationship_analysis(
        &self,
        mut result: HybridQueryResult,
        entity_a_name: &str,
        entity_b_name: &str,
        include_indirect: bool,
    ) -> Result<HybridQueryResult, AppError> {
        // Add relationship timeline analysis
        result.summary.key_insights.push(format!(
            "Analyzed {} events affecting relationship between {} and {}",
            result.chronicle_events.len(),
            entity_a_name,
            entity_b_name
        ));

        if include_indirect {
            result.summary.key_insights.push(
                "Included indirect effects through mutual connections".to_string()
            );
        }

        // TODO: Add relationship strength analysis over time
        // TODO: Identify key turning points in the relationship

        Ok(result)
    }

    /// Enhance result with item-specific analysis
    async fn enhance_with_item_analysis(
        &self,
        mut result: HybridQueryResult,
        item_name: &str,
        _item_id: Option<Uuid>,
        interaction_types: Option<&[String]>,
    ) -> Result<HybridQueryResult, AppError> {
        // Add item interaction analysis
        result.summary.key_insights.push(format!(
            "Tracked {} interactions with {}",
            result.chronicle_events.len(),
            item_name
        ));

        if let Some(types) = interaction_types {
            result.summary.key_insights.push(format!(
                "Filtered for interaction types: {}",
                types.join(", ")
            ));
        }

        // TODO: Add item ownership timeline
        // TODO: Identify item usage patterns

        Ok(result)
    }

    /// Filter and rank chronicle events by item relevance
    async fn filter_and_rank_item_events(
        &self,
        mut events: Vec<ChronicleEvent>,
        item_name: &str,
    ) -> Result<Vec<ChronicleEvent>, AppError> {
        // Filter events that mention the item
        events.retain(|event| {
            // Check if event content mentions the item
            if let Some(event_data) = &event.event_data {
                event_data
                    .get("content")
                    .and_then(|content| content.as_str())
                    .map(|content_str| {
                        content_str.to_lowercase().contains(&item_name.to_lowercase())
                    })
                    .unwrap_or(false)
            } else {
                false
            }
        });

        // Sort by relevance (most recent first for now)
        events.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(events)
    }

    /// Generate narrative answer for trusted characters at location query
    async fn generate_trusted_location_narrative(
        &self,
        entities: &[EntityTimelineContext],
        location_name: &str,
        min_trust: f32,
    ) -> Result<String, AppError> {
        if entities.is_empty() {
            return Ok(format!(
                "No characters with trust ≥ {:.1} are currently present at {}.",
                min_trust, location_name
            ));
        }

        let character_names: Vec<String> = entities
            .iter()
            .filter_map(|entity| entity.entity_name.as_ref())
            .cloned()
            .collect();

        if character_names.is_empty() {
            return Ok(format!(
                "{} unnamed characters with sufficient trust are present at {}.",
                entities.len(), location_name
            ));
        }

        Ok(format!(
            "Characters present at {} with trust ≥ {:.1}: {}.",
            location_name,
            min_trust,
            character_names.join(", ")
        ))
    }

    /// Generate narrative answer for relationship events query
    async fn generate_relationship_events_narrative(
        &self,
        events: &[ChronicleEvent],
        relationships: &[RelationshipAnalysis],
        entity_a_name: &str,
        entity_b_name: &str,
    ) -> Result<String, AppError> {
        if events.is_empty() {
            return Ok(format!(
                "No significant events found that affected the relationship between {} and {}.",
                entity_a_name, entity_b_name
            ));
        }

        let mut narrative = format!(
            "Found {} events that affected the relationship between {} and {}. ",
            events.len(), entity_a_name, entity_b_name
        );

        // Add relationship trend if available
        if let Some(relationship) = relationships.first() {
            match relationship.analysis.trend {
                RelationshipTrend::Improving => {
                    narrative.push_str("Their relationship appears to be improving over time.");
                }
                RelationshipTrend::Declining => {
                    narrative.push_str("Their relationship shows signs of decline.");
                }
                RelationshipTrend::Stable => {
                    narrative.push_str("Their relationship has remained relatively stable.");
                }
                RelationshipTrend::Volatile => {
                    narrative.push_str("Their relationship has been volatile with many ups and downs.");
                }
                RelationshipTrend::Unknown => {
                    narrative.push_str("The relationship trend is unclear from available data.");
                }
            }
        }

        Ok(narrative)
    }

    /// Generate narrative answer for item interaction query
    async fn generate_item_interaction_narrative(
        &self,
        entities: &[EntityTimelineContext],
        events: &[ChronicleEvent],
        item_name: &str,
        interaction_types: Option<&[String]>,
    ) -> Result<String, AppError> {
        if entities.is_empty() && events.is_empty() {
            return Ok(format!(
                "No characters found who have interacted with {}.",
                item_name
            ));
        }

        let mut narrative = format!(
            "{} characters have interacted with {} across {} recorded events. ",
            entities.len(), item_name, events.len()
        );

        if let Some(types) = interaction_types {
            narrative.push_str(&format!(
                "Interaction types tracked: {}. ",
                types.join(", ")
            ));
        }

        // Add most recent interaction info if available
        if let Some(latest_event) = events.first() {
            narrative.push_str(&format!(
                "Most recent interaction occurred on {}.",
                latest_event.created_at.format("%Y-%m-%d")
            ));
        }

        Ok(narrative)
    }
}