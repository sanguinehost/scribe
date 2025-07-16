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

/// Represents a state change extracted from an event
#[derive(Debug, Clone)]
struct StateChange {
    /// The component type being changed
    component_type: String,
    /// The type of change (increase, decrease, set, add_item, remove_item)
    change_type: String,
    /// The magnitude of the change (for numeric values)
    change_value: f64,
    /// The specific field being changed
    field_name: String,
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
        let timeline_events = self.build_entity_timeline(entity_id, events, query.user_id).await?;

        // Get current relationships
        let relationships = if query.include_relationships {
            self.get_entity_relationships(entity_id, query.user_id).await?
        } else {
            Vec::new()
        };

        // Calculate relevance score based on query and entity context
        let relevance_score = self.calculate_entity_relevance_score(entity_id, &timeline_events, &current_state, query).await?;

        Ok(EntityTimelineContext {
            entity_id,
            entity_name: self.extract_entity_name(entity_id).await?,
            current_state,
            timeline_events,
            relationships,
            relevance_score,
        })
    }

    /// Get current state for an entity
    async fn get_entity_current_state(&self, entity_id: Uuid, user_id: Uuid) -> Result<EntityStateSnapshot, AppError> {
        debug!("Getting current state for entity: {}", entity_id);
        
        // Check if we would use cache (based on config)
        if self.config.enable_entity_caching {
            // In a real implementation, we'd check cache here
            // For now, we simulate a cache miss
            self.metrics.record_cache_miss();
        }
        
        // Record that we're querying the entity manager (DB)
        self.metrics.record_db_query();
        
        // Use entity manager to get current state
        match self.entity_manager.get_entity(user_id, entity_id).await {
            Ok(Some(entity_query_result)) => {
                // Convert ECS entity query result to EntityStateSnapshot
                let mut components: HashMap<String, serde_json::Value> = HashMap::new();
                
                // Process each component
                for ecs_component in entity_query_result.components {
                    components.insert(ecs_component.component_type.clone(), ecs_component.component_data);
                }
                
                // Generate status indicators based on components
                let mut status_indicators = Vec::new();
                if components.contains_key("health") {
                    status_indicators.push("has_health".to_string());
                }
                if components.contains_key("position") {
                    status_indicators.push("has_position".to_string());
                }
                if components.contains_key("inventory") {
                    status_indicators.push("has_inventory".to_string());
                }
                
                // Generate archetype signature from component types
                let mut comp_types: Vec<_> = components.keys().cloned().collect();
                comp_types.sort();
                let archetype_signature = comp_types.join(",");
                
                Ok(EntityStateSnapshot {
                    entity_id,
                    archetype_signature,
                    components,
                    snapshot_time: entity_query_result.entity.updated_at,
                    status_indicators,
                })
            }
            Ok(None) => {
                debug!("Entity not found: {}", entity_id);
                // Entity doesn't exist
                Ok(EntityStateSnapshot {
                    entity_id,
                    archetype_signature: "not_found".to_string(),
                    components: HashMap::new(),
                    snapshot_time: chrono::Utc::now(),
                    status_indicators: vec!["entity_not_found".to_string()],
                })
            }
            Err(e) => {
                debug!("Entity manager unavailable or error: {}", e);
                // Fallback to empty snapshot if entity manager fails
                Ok(EntityStateSnapshot {
                    entity_id,
                    archetype_signature: "unknown".to_string(),
                    components: HashMap::new(),
                    snapshot_time: chrono::Utc::now(),
                    status_indicators: vec!["ecs_unavailable".to_string()],
                })
            }
        }
    }

    /// Build timeline events for an entity
    async fn build_entity_timeline(&self, entity_id: Uuid, events: &[ChronicleEvent], user_id: Uuid) -> Result<Vec<TimelineEvent>, AppError> {
        let mut timeline_events = Vec::new();

        for event in events {
            // Check if entity was involved in this event
            if self.entity_involved_in_event(entity_id, event).await? {
                let significance_score = self.calculate_event_significance(entity_id, event).await?;
                let timeline_event = TimelineEvent {
                    event: event.clone(),
                    entity_state_at_time: {
                        match self.reconstruct_entity_state_at_event(entity_id, event, user_id).await? {
                            Some(state) => Some(serde_json::to_value(state).unwrap_or(serde_json::Value::Null)),
                            None => None,
                        }
                    },
                    co_participants: self.extract_co_participants(entity_id, event).await?,
                    significance_score,
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
    async fn extract_co_participants(&self, entity_id: Uuid, event: &ChronicleEvent) -> Result<Vec<Uuid>, AppError> {
        let mut co_participants = Vec::new();
        
        // Extract from actors list
        if let Ok(actors) = event.get_actors() {
            for actor in actors {
                if actor.entity_id != entity_id {
                    co_participants.push(actor.entity_id);
                }
            }
        }
        
        // Extract from event_data JSON
        if let Some(event_data) = &event.event_data {
            // Check actors array in event_data
            if let Some(actors_value) = event_data.get("actors") {
                if let Some(actors_array) = actors_value.as_array() {
                    for actor_value in actors_array {
                        if let Some(actor_entity_id) = actor_value.get("entity_id") {
                            if let Some(actor_id_str) = actor_entity_id.as_str() {
                                if let Ok(actor_uuid) = Uuid::parse_str(actor_id_str) {
                                    if actor_uuid != entity_id {
                                        co_participants.push(actor_uuid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Check participants array in event_data
            if let Some(participants_value) = event_data.get("participants") {
                if let Some(participants_array) = participants_value.as_array() {
                    for participant_value in participants_array {
                        if let Some(participant_str) = participant_value.as_str() {
                            if let Ok(participant_uuid) = Uuid::parse_str(participant_str) {
                                if participant_uuid != entity_id {
                                    co_participants.push(participant_uuid);
                                }
                            }
                        }
                    }
                }
            }
            
            // Check for target/subject entity IDs in event_data
            for field in &["target_entity_id", "subject_entity_id", "related_entity_id"] {
                if let Some(target_value) = event_data.get(field) {
                    if let Some(target_str) = target_value.as_str() {
                        if let Ok(target_uuid) = Uuid::parse_str(target_str) {
                            if target_uuid != entity_id {
                                co_participants.push(target_uuid);
                            }
                        }
                    }
                }
            }
            
            // Check for entities mentioned in nested objects
            if let Some(details) = event_data.get("details") {
                if let Some(details_obj) = details.as_object() {
                    for (_, value) in details_obj {
                        if let Some(entity_str) = value.as_str() {
                            if let Ok(entity_uuid) = Uuid::parse_str(entity_str) {
                                if entity_uuid != entity_id {
                                    co_participants.push(entity_uuid);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Remove duplicates
        co_participants.sort();
        co_participants.dedup();
        
        debug!("Extracted {} co-participants for entity {} from event {}", 
               co_participants.len(), entity_id, event.id);
        
        Ok(co_participants)
    }

    /// Get relationships for an entity
    async fn get_entity_relationships(&self, entity_id: Uuid, user_id: Uuid) -> Result<Vec<RelationshipContext>, AppError> {
        // Query ECS for current relationships
        self.metrics.record_db_query();
        
        // Check cache first
        if self.config.enable_entity_caching {
            // For now, cache miss - in production we'd check Redis here
            self.metrics.record_cache_miss();
        }
        
        // Get relationships from entity manager
        let relationships = self.entity_manager.get_relationships(user_id, entity_id).await?;
        
        // Convert ECS relationships to RelationshipContext format
        let mut relationship_contexts = Vec::new();
        for relationship in relationships {
            // Create relationship data JSON from trust, affection, and metadata
            let mut relationship_data = serde_json::json!({
                "trust": relationship.trust,
                "affection": relationship.affection
            });
            
            // Merge metadata into relationship data
            if let serde_json::Value::Object(data_obj) = &mut relationship_data {
                for (key, value) in &relationship.metadata {
                    data_obj.insert(key.clone(), value.clone());
                }
            }
            
            let relationship_context = RelationshipContext {
                from_entity_id: entity_id,
                to_entity_id: relationship.target_entity_id,
                relationship_type: relationship.relationship_type.clone(),
                relationship_data,
                established_at: None, // ECS Relationship doesn't have this field
                last_updated: None,   // ECS Relationship doesn't have this field
            };
            relationship_contexts.push(relationship_context);
        }
        
        debug!("Retrieved {} relationships for entity {}", relationship_contexts.len(), entity_id);
        Ok(relationship_contexts)
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
        events: &[ChronicleEvent],
    ) -> Result<RelationshipAnalysis, AppError> {
        // Get current relationships for both entities
        let mut current_relationship = None;
        
        // Check relationships from entity A to entity B
        if let Ok(relationships_a) = self.get_entity_relationships(entity_a, 
            self.get_user_id_from_events(events).unwrap_or(Uuid::nil())
        ).await {
            current_relationship = relationships_a.into_iter()
                .find(|r| r.to_entity_id == entity_b);
        }
        
        // If no direct relationship found, check from B to A
        if current_relationship.is_none() {
            if let Ok(relationships_b) = self.get_entity_relationships(entity_b, 
                self.get_user_id_from_events(events).unwrap_or(Uuid::nil())
            ).await {
                current_relationship = relationships_b.into_iter()
                    .find(|r| r.to_entity_id == entity_a)
                    .map(|mut r| {
                        // Reverse the relationship direction for consistency
                        r.from_entity_id = entity_a;
                        r.to_entity_id = entity_b;
                        r
                    });
            }
        }
        
        // Analyze relationship history from chronicle events
        let relationship_history = self.extract_relationship_history(entity_a, entity_b, events).await?;
        
        // Calculate relationship metrics
        let metrics = self.calculate_relationship_metrics(
            &current_relationship,
            &relationship_history,
            events
        ).await?;
        
        Ok(RelationshipAnalysis {
            from_entity_id: entity_a,
            to_entity_id: entity_b,
            current_relationship,
            relationship_history,
            analysis: metrics,
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

        // Add relationship strength analysis over time
        if let Some(first_entity) = result.entities.first() {
            if let Some(second_entity) = result.entities.get(1) {
                // Analyze relationship between first two entities
                let relationship_analysis = self.analyze_entity_pair_relationship(
                    first_entity.entity_id,
                    second_entity.entity_id,
                    &result.chronicle_events
                ).await?;
                
                // Add strength analysis to insights
                result.summary.key_insights.push(format!(
                    "Relationship strength: {:.2}, stability: {:.2}, trend: {:?}",
                    relationship_analysis.analysis.strength,
                    relationship_analysis.analysis.stability,
                    relationship_analysis.analysis.trend
                ));
                
                // Identify key turning points in the relationship
                if relationship_analysis.relationship_history.len() >= 2 {
                    let turning_points = self.identify_relationship_turning_points(
                        &relationship_analysis.relationship_history
                    );
                    
                    if !turning_points.is_empty() {
                        result.summary.key_insights.push(format!(
                            "Key turning points identified: {} significant relationship changes",
                            turning_points.len()
                        ));
                        
                        // Add details about the most significant turning point
                        if let Some(most_significant) = turning_points.first() {
                            result.summary.key_insights.push(format!(
                                "Most significant change: {} (strength change: {:.2})",
                                most_significant.relationship_type,
                                most_significant.strength_change
                            ));
                        }
                    }
                }
                
                // Add historical context
                if relationship_analysis.analysis.interaction_count > 0 {
                    result.summary.key_insights.push(format!(
                        "Total interactions tracked: {}",
                        relationship_analysis.analysis.interaction_count
                    ));
                }
            }
        }

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

    /// Calculate entity relevance score based on query and entity context
    async fn calculate_entity_relevance_score(
        &self,
        entity_id: Uuid,
        timeline_events: &[TimelineEvent],
        current_state: &Option<EntityStateSnapshot>,
        query: &HybridQuery,
    ) -> Result<f32, AppError> {
        let mut relevance_score = 0.0f32;
        let mut scoring_factors = 0;

        // Get query text for comparison
        let query_text = match &query.query_type {
            HybridQueryType::NarrativeQuery { query_text, .. } => query_text.as_str(),
            HybridQueryType::RelationshipHistory { entity_a, entity_b, .. } => {
                // For relationship queries, consider both entity names
                return Ok(if entity_a.to_lowercase().contains(&entity_id.to_string()) || 
                            entity_b.to_lowercase().contains(&entity_id.to_string()) {
                    0.9 // High relevance for entities directly involved in relationship query
                } else {
                    0.3 // Lower relevance for other entities
                });
            }
            HybridQueryType::LocationQuery { location_name, .. } => {
                // For location queries, check if entity is at that location
                if let Some(state) = current_state {
                    if let Some(position_data) = state.components.get("position") {
                        if position_data.to_string().to_lowercase().contains(&location_name.to_lowercase()) {
                            return Ok(0.85); // High relevance for entities at the queried location
                        }
                    }
                }
                return Ok(0.2); // Lower relevance for entities not at the location
            }
            HybridQueryType::EntityTimeline { .. } => {
                // Entity timeline queries are always relevant to the entity
                return Ok(0.9);
            }
            HybridQueryType::EventParticipants { .. } => {
                // Event participant queries have moderate relevance
                return Ok(0.6);
            }
            HybridQueryType::EntityStateAtTime { .. } => {
                // Entity state queries are highly relevant to the entity
                return Ok(0.9);
            }
            _ => {
                // For other query types, use default relevance
                return Ok(0.5);
            }
        };

        // Factor 1: Entity name similarity to query (30% weight)
        if let Ok(Some(entity_name)) = self.extract_entity_name(entity_id).await {
            let name_similarity = self.calculate_text_similarity(&entity_name, query_text);
            relevance_score += name_similarity * 0.3;
            scoring_factors += 1;
        }

        // Factor 2: Current state relevance (25% weight)
        if let Some(state) = current_state {
            let state_similarity = self.calculate_state_relevance(state, query_text);
            relevance_score += state_similarity * 0.25;
            scoring_factors += 1;
        }

        // Factor 3: Timeline event relevance (30% weight)
        if !timeline_events.is_empty() {
            let event_similarity = self.calculate_timeline_relevance(timeline_events, query_text);
            relevance_score += event_similarity * 0.3;
            scoring_factors += 1;
        }

        // Factor 4: Recency boost (15% weight)
        if !timeline_events.is_empty() {
            let recency_score = self.calculate_recency_score(timeline_events);
            relevance_score += recency_score * 0.15;
            scoring_factors += 1;
        }

        // Normalize by number of factors and clamp to [0.0, 1.0]
        let final_score = if scoring_factors > 0 {
            (relevance_score / scoring_factors as f32).min(1.0).max(0.0)
        } else {
            0.1 // Default minimal relevance if no factors available
        };

        debug!("Entity {} relevance score: {:.3} (factors: {})", entity_id, final_score, scoring_factors);
        Ok(final_score)
    }

    /// Calculate text similarity using simple keyword matching
    /// TODO: Replace with embedding-based similarity when available
    fn calculate_text_similarity(&self, text1: &str, text2: &str) -> f32 {
        let text1_lower = text1.to_lowercase();
        let text2_lower = text2.to_lowercase();
        
        let words1: std::collections::HashSet<&str> = text1_lower.split_whitespace().collect();
        let words2: std::collections::HashSet<&str> = text2_lower.split_whitespace().collect();
        
        if words1.is_empty() || words2.is_empty() {
            return 0.0;
        }

        let intersection = words1.intersection(&words2).count();
        let union = words1.union(&words2).count();
        
        if union == 0 {
            0.0
        } else {
            intersection as f32 / union as f32
        }
    }

    /// Calculate relevance based on entity state components
    fn calculate_state_relevance(&self, state: &EntityStateSnapshot, query_text: &str) -> f32 {
        let mut relevance = 0.0f32;
        let mut component_count = 0;

        // Check component types for relevance
        for (component_type, component_data) in &state.components {
            component_count += 1;
            
            // Check if component type matches query
            if query_text.to_lowercase().contains(&component_type.to_lowercase()) {
                relevance += 0.7;
            }
            
            // Check component data for keyword matches
            let data_str = component_data.to_string().to_lowercase();
            if data_str.contains(&query_text.to_lowercase()) {
                relevance += 0.5;
            }
        }

        // Check status indicators
        for indicator in &state.status_indicators {
            if query_text.to_lowercase().contains(&indicator.to_lowercase()) {
                relevance += 0.3;
            }
        }

        // Normalize by component count
        if component_count > 0 {
            relevance / component_count as f32
        } else {
            0.0
        }
    }

    /// Calculate relevance based on timeline events
    fn calculate_timeline_relevance(&self, timeline_events: &[TimelineEvent], query_text: &str) -> f32 {
        if timeline_events.is_empty() {
            return 0.0;
        }

        let mut total_relevance = 0.0f32;
        
        for event in timeline_events {
            let mut event_relevance = 0.0f32;
            
            // Check event summary for relevance
            if event.event.summary.to_lowercase().contains(&query_text.to_lowercase()) {
                event_relevance += 0.8;
            }
            
            // Check event type for relevance
            if query_text.to_lowercase().contains(&event.event.event_type.to_lowercase()) {
                event_relevance += 0.6;
            }
            
            // Weight by significance score
            event_relevance *= event.significance_score;
            
            total_relevance += event_relevance;
        }

        // Average relevance across all events
        total_relevance / timeline_events.len() as f32
    }

    /// Calculate recency score (more recent events get higher scores)
    fn calculate_recency_score(&self, timeline_events: &[TimelineEvent]) -> f32 {
        if timeline_events.is_empty() {
            return 0.0;
        }

        let now = chrono::Utc::now();
        let mut weighted_score = 0.0f32;
        let mut total_weight = 0.0f32;

        for event in timeline_events {
            let event_age = now.signed_duration_since(event.event.created_at);
            let days_ago = event_age.num_days() as f32;
            
            // Exponential decay: more recent events get higher weights
            let recency_weight = (-days_ago / 30.0).exp(); // 30-day half-life
            
            weighted_score += recency_weight * event.significance_score;
            total_weight += recency_weight;
        }

        if total_weight > 0.0 {
            weighted_score / total_weight
        } else {
            0.0
        }
    }

    /// Calculate event significance score using multi-factor analysis
    async fn calculate_event_significance(&self, entity_id: Uuid, event: &ChronicleEvent) -> Result<f32, AppError> {
        let mut significance_score = 0.0f32;
        let mut scoring_factors = 0;

        // Factor 1: Event type significance (25% weight)
        let event_type_score = self.calculate_event_type_significance(&event.event_type);
        significance_score += event_type_score * 0.25;
        scoring_factors += 1;

        // Factor 2: Entity role in event (30% weight)
        let entity_role_score = self.calculate_entity_role_significance(entity_id, event).await?;
        significance_score += entity_role_score * 0.30;
        scoring_factors += 1;

        // Factor 3: Event complexity/richness (20% weight)
        let complexity_score = self.calculate_event_complexity_significance(event);
        significance_score += complexity_score * 0.20;
        scoring_factors += 1;

        // Factor 4: Event recency (15% weight)
        let recency_score = self.calculate_event_recency_significance(event);
        significance_score += recency_score * 0.15;
        scoring_factors += 1;

        // Factor 5: Co-participant count (10% weight)
        let co_participants = self.extract_co_participants(entity_id, event).await?;
        let participant_score = self.calculate_participant_significance(&co_participants);
        significance_score += participant_score * 0.10;
        scoring_factors += 1;

        // Normalize and clamp to [0.0, 1.0]
        let final_score = if scoring_factors > 0 {
            (significance_score / scoring_factors as f32).min(1.0).max(0.0)
        } else {
            0.5 // Default significance if no factors available
        };

        debug!("Event {} significance for entity {}: {:.3}", event.id, entity_id, final_score);
        Ok(final_score)
    }

    /// Calculate significance based on event type
    fn calculate_event_type_significance(&self, event_type: &str) -> f32 {
        // Assign significance scores based on event type
        match event_type.to_lowercase().as_str() {
            // High significance events
            "death" | "birth" | "marriage" | "battle" | "betrayal" | "discovery" => 0.9,
            "transformation" | "revelation" | "conquest" | "defeat" | "creation" => 0.9,
            
            // Medium-high significance events
            "combat" | "conflict" | "alliance" | "romance" | "quest_completion" => 0.8,
            "trade" | "negotiation" | "ceremony" | "ritual" | "magic_use" => 0.8,
            
            // Medium significance events
            "movement" | "exploration" | "conversation" | "meeting" | "departure" => 0.6,
            "acquisition" | "crafting" | "learning" | "teaching" | "healing" => 0.6,
            
            // Lower significance events
            "observation" | "rest" | "maintenance" | "routine" | "preparation" => 0.4,
            "eating" | "sleeping" | "waiting" | "thinking" | "planning" => 0.4,
            
            // Default for unknown event types
            _ => 0.5
        }
    }

    /// Calculate significance based on entity's role in the event
    async fn calculate_entity_role_significance(&self, entity_id: Uuid, event: &ChronicleEvent) -> Result<f32, AppError> {
        let mut role_score = 0.5f32; // Default score
        
        // Check if entity is primary actor
        if let Ok(actors) = event.get_actors() {
            let actor_count = actors.len();
            let is_primary_actor = actors.iter().any(|actor| actor.entity_id == entity_id);
            
            if is_primary_actor {
                // Primary actor gets higher significance
                role_score = match actor_count {
                    1 => 0.9,        // Sole actor - highest significance
                    2..=3 => 0.8,    // Small group - high significance
                    4..=6 => 0.7,    // Medium group - medium-high significance
                    _ => 0.6,        // Large group - medium significance
                };
            }
        }
        
        // Check event data for additional role indicators
        if let Some(event_data) = &event.event_data {
            // Check if entity is mentioned as initiator, target, or subject
            let data_str = event_data.to_string().to_lowercase();
            let entity_str = entity_id.to_string().to_lowercase();
            
            if data_str.contains(&format!("\"initiator\":\"{}", entity_str)) ||
               data_str.contains(&format!("\"subject\":\"{}", entity_str)) {
                role_score += 0.2; // Boost for being initiator/subject
            }
            
            if data_str.contains(&format!("\"target\":\"{}", entity_str)) {
                role_score += 0.15; // Boost for being target
            }
        }
        
        Ok(role_score.min(1.0))
    }

    /// Calculate significance based on event complexity and data richness
    fn calculate_event_complexity_significance(&self, event: &ChronicleEvent) -> f32 {
        let mut complexity_score = 0.3f32; // Base score
        
        // Factor in summary length and detail
        let summary_length = event.summary.len();
        complexity_score += match summary_length {
            0..=50 => 0.0,      // Very short - low complexity
            51..=150 => 0.2,    // Short - medium complexity
            151..=300 => 0.4,   // Medium - good complexity
            301..=500 => 0.6,   // Long - high complexity
            _ => 0.8,           // Very long - very high complexity
        };
        
        // Factor in event data richness
        if let Some(event_data) = &event.event_data {
            let data_fields = if let Some(obj) = event_data.as_object() {
                obj.len()
            } else {
                0
            };
            
            complexity_score += match data_fields {
                0..=2 => 0.0,     // Minimal data
                3..=5 => 0.2,     // Basic data
                6..=10 => 0.4,    // Rich data
                11..=15 => 0.6,   // Very rich data
                _ => 0.8,         // Extremely rich data
            };
        }
        
        complexity_score.min(1.0)
    }

    /// Calculate significance based on event recency
    fn calculate_event_recency_significance(&self, event: &ChronicleEvent) -> f32 {
        let now = chrono::Utc::now();
        let event_age = now.signed_duration_since(event.created_at);
        let hours_ago = event_age.num_hours() as f32;
        
        // Exponential decay for recency - recent events are more significant
        if hours_ago < 0.0 {
            1.0 // Future events (edge case) get max significance
        } else {
            // 24-hour half-life for recency significance
            (-hours_ago / 24.0).exp().min(1.0)
        }
    }

    /// Calculate significance based on number of co-participants
    fn calculate_participant_significance(&self, co_participants: &[Uuid]) -> f32 {
        match co_participants.len() {
            0 => 0.3,        // Solo event - lower significance
            1 => 0.5,        // Two-person event - medium significance
            2..=3 => 0.7,    // Small group - higher significance
            4..=6 => 0.9,    // Medium group - high significance
            _ => 1.0,        // Large group - maximum significance
        }
    }

    /// Reconstruct entity state at the time of a specific event
    async fn reconstruct_entity_state_at_event(
        &self,
        entity_id: Uuid,
        event: &ChronicleEvent,
        user_id: Uuid,
    ) -> Result<Option<EntityStateSnapshot>, AppError> {
        // If we have current state, try to reconstruct historical state
        if let Ok(current_state) = self.get_entity_current_state(entity_id, user_id).await {
            // For reconstruction, we need to work backwards from current state
            // using chronicle events to determine what changed
            
            // Get all events after this event timestamp to work backwards
            let events_after = self.get_events_after_timestamp(entity_id, event.created_at).await?;
            
            // Start with current state and work backwards
            let mut reconstructed_state = current_state.clone();
            
            // Process events in reverse chronological order
            for later_event in events_after.iter().rev() {
                // Apply reverse changes from this event
                if let Ok(state_changes) = self.extract_state_changes_from_event(later_event).await {
                    self.apply_reverse_state_changes(&mut reconstructed_state, &state_changes)?;
                }
            }
            
            // Apply any state changes from the target event itself
            if let Ok(state_changes) = self.extract_state_changes_from_event(event).await {
                self.apply_state_changes(&mut reconstructed_state, &state_changes)?;
            }
            
            // Update the snapshot time to the event time
            reconstructed_state.snapshot_time = event.created_at;
            
            Ok(Some(reconstructed_state))
        } else {
            // No current state available, try to reconstruct from event data
            if let Ok(state_from_event) = self.build_state_from_event(entity_id, event).await {
                Ok(Some(state_from_event))
            } else {
                // Unable to reconstruct state
                Ok(None)
            }
        }
    }

    /// Get chronicle events after a specific timestamp for an entity
    async fn get_events_after_timestamp(
        &self,
        entity_id: Uuid,
        timestamp: DateTime<Utc>,
    ) -> Result<Vec<ChronicleEvent>, AppError> {
        use diesel::prelude::*;
        use crate::schema::chronicle_events;
        
        let conn = self.db_pool.get().await?;
        
        // Query for events after the timestamp where entity is involved
        let events = conn
            .interact(move |conn| {
                chronicle_events::table
                    .filter(chronicle_events::created_at.gt(timestamp))
                    .order(chronicle_events::created_at.asc())
                    .load::<ChronicleEvent>(conn)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("Failed to query events: {e}")))?
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to load events: {e}")))?;
        
        // Filter for events involving this entity
        let mut relevant_events = Vec::new();
        for event in events {
            if self.entity_involved_in_event(entity_id, &event).await? {
                relevant_events.push(event);
            }
        }
        
        Ok(relevant_events)
    }

    /// Extract state changes from an event
    async fn extract_state_changes_from_event(
        &self,
        event: &ChronicleEvent,
    ) -> Result<Vec<StateChange>, AppError> {
        let mut state_changes = Vec::new();
        
        // Parse event data for state changes
        if let Some(event_data) = &event.event_data {
            // Look for common state change patterns
            if let Some(health_change) = event_data.get("health_change") {
                if let Some(change_value) = health_change.as_f64() {
                    state_changes.push(StateChange {
                        component_type: "health".to_string(),
                        change_type: if change_value > 0.0 { "increase" } else { "decrease" }.to_string(),
                        change_value: change_value.abs(),
                        field_name: "current_health".to_string(),
                    });
                }
            }
            
            if let Some(location_change) = event_data.get("location_change") {
                if let Some(new_location) = location_change.as_str() {
                    state_changes.push(StateChange {
                        component_type: "position".to_string(),
                        change_type: "set".to_string(),
                        change_value: 0.0,
                        field_name: "location".to_string(),
                    });
                }
            }
            
            if let Some(inventory_change) = event_data.get("inventory_change") {
                if let Some(item_added) = inventory_change.get("added") {
                    state_changes.push(StateChange {
                        component_type: "inventory".to_string(),
                        change_type: "add_item".to_string(),
                        change_value: 1.0,
                        field_name: "items".to_string(),
                    });
                }
                if let Some(item_removed) = inventory_change.get("removed") {
                    state_changes.push(StateChange {
                        component_type: "inventory".to_string(),
                        change_type: "remove_item".to_string(),
                        change_value: 1.0,
                        field_name: "items".to_string(),
                    });
                }
            }
            
            // Look for experience/level changes
            if let Some(exp_change) = event_data.get("experience_change") {
                if let Some(exp_value) = exp_change.as_f64() {
                    state_changes.push(StateChange {
                        component_type: "character_stats".to_string(),
                        change_type: if exp_value > 0.0 { "increase" } else { "decrease" }.to_string(),
                        change_value: exp_value.abs(),
                        field_name: "experience".to_string(),
                    });
                }
            }
        }
        
        Ok(state_changes)
    }

    /// Apply reverse state changes to reconstruct earlier state
    fn apply_reverse_state_changes(
        &self,
        state: &mut EntityStateSnapshot,
        changes: &[StateChange],
    ) -> Result<(), AppError> {
        for change in changes {
            if let Some(component) = state.components.get_mut(&change.component_type) {
                match change.change_type.as_str() {
                    "increase" => {
                        // Reverse an increase by decreasing
                        if let Some(current_value) = component.get(&change.field_name).and_then(|v| v.as_f64()) {
                            let new_value = current_value - change.change_value;
                            component[&change.field_name] = serde_json::Value::Number(
                                serde_json::Number::from_f64(new_value).unwrap_or(serde_json::Number::from(0))
                            );
                        }
                    }
                    "decrease" => {
                        // Reverse a decrease by increasing
                        if let Some(current_value) = component.get(&change.field_name).and_then(|v| v.as_f64()) {
                            let new_value = current_value + change.change_value;
                            component[&change.field_name] = serde_json::Value::Number(
                                serde_json::Number::from_f64(new_value).unwrap_or(serde_json::Number::from(0))
                            );
                        }
                    }
                    "add_item" => {
                        // Reverse item addition by removing item
                        if let Some(items) = component.get_mut(&change.field_name).and_then(|v| v.as_array_mut()) {
                            if let Some(last_item) = items.last() {
                                items.pop();
                            }
                        }
                    }
                    "remove_item" => {
                        // Cannot reliably reverse item removal without more context
                        // This would require storing the removed item data
                        debug!("Cannot reverse item removal without original item data");
                    }
                    _ => {
                        debug!("Unknown change type for reversal: {}", change.change_type);
                    }
                }
            }
        }
        Ok(())
    }

    /// Apply state changes to an entity state
    fn apply_state_changes(
        &self,
        state: &mut EntityStateSnapshot,
        changes: &[StateChange],
    ) -> Result<(), AppError> {
        for change in changes {
            if let Some(component) = state.components.get_mut(&change.component_type) {
                match change.change_type.as_str() {
                    "increase" => {
                        if let Some(current_value) = component.get(&change.field_name).and_then(|v| v.as_f64()) {
                            let new_value = current_value + change.change_value;
                            component[&change.field_name] = serde_json::Value::Number(
                                serde_json::Number::from_f64(new_value).unwrap_or(serde_json::Number::from(0))
                            );
                        }
                    }
                    "decrease" => {
                        if let Some(current_value) = component.get(&change.field_name).and_then(|v| v.as_f64()) {
                            let new_value = current_value - change.change_value;
                            component[&change.field_name] = serde_json::Value::Number(
                                serde_json::Number::from_f64(new_value).unwrap_or(serde_json::Number::from(0))
                            );
                        }
                    }
                    "set" => {
                        // Set operations would need the new value from event data
                        debug!("Set operation needs implementation with event data");
                    }
                    "add_item" => {
                        if let Some(items) = component.get_mut(&change.field_name).and_then(|v| v.as_array_mut()) {
                            // Add placeholder item (real implementation would need item data)
                            items.push(serde_json::Value::String("reconstructed_item".to_string()));
                        }
                    }
                    "remove_item" => {
                        if let Some(items) = component.get_mut(&change.field_name).and_then(|v| v.as_array_mut()) {
                            items.pop();
                        }
                    }
                    _ => {
                        debug!("Unknown change type: {}", change.change_type);
                    }
                }
            }
        }
        Ok(())
    }

    /// Build entity state from event data when no current state exists
    async fn build_state_from_event(
        &self,
        entity_id: Uuid,
        event: &ChronicleEvent,
    ) -> Result<EntityStateSnapshot, AppError> {
        let mut components = HashMap::new();
        
        // Try to extract entity state from event data
        if let Some(event_data) = &event.event_data {
            // Look for entity state snapshots in event data
            if let Some(entity_states) = event_data.get("entity_states") {
                if let Some(entity_state) = entity_states.get(entity_id.to_string()) {
                    if let Some(state_obj) = entity_state.as_object() {
                        for (key, value) in state_obj {
                            let mut component_data = HashMap::new();
                            component_data.insert("data".to_string(), value.clone());
                            components.insert(key.clone(), serde_json::Value::Object(
                                component_data.into_iter().collect()
                            ));
                        }
                    }
                }
            }
            
            // If no direct state, infer from event context
            if components.is_empty() {
                // Infer basic components from event participation
                if let Ok(actors) = event.get_actors() {
                    for actor in actors {
                        if actor.entity_id == entity_id {
                            // Add basic character component
                            let mut character_data = HashMap::new();
                            character_data.insert("entity_id".to_string(), serde_json::Value::String(actor.entity_id.to_string()));
                            character_data.insert("role".to_string(), serde_json::Value::String(format!("{:?}", actor.role)));
                            if let Some(context) = &actor.context {
                                character_data.insert("context".to_string(), serde_json::Value::String(context.clone()));
                            }
                            components.insert("character".to_string(), serde_json::Value::Object(
                                character_data.into_iter().collect()
                            ));
                        }
                    }
                }
            }
        }
        
        // Generate status indicators
        let mut status_indicators = Vec::new();
        if components.contains_key("health") {
            status_indicators.push("has_health".to_string());
        }
        if components.contains_key("position") {
            status_indicators.push("has_position".to_string());
        }
        if components.contains_key("inventory") {
            status_indicators.push("has_inventory".to_string());
        }
        if components.is_empty() {
            status_indicators.push("reconstructed_minimal".to_string());
        } else {
            status_indicators.push("reconstructed_from_event".to_string());
        }
        
        // Generate archetype signature
        let mut comp_types: Vec<_> = components.keys().cloned().collect();
        comp_types.sort();
        let archetype_signature = if comp_types.is_empty() {
            "unknown".to_string()
        } else {
            comp_types.join(",")
        };
        
        Ok(EntityStateSnapshot {
            entity_id,
            archetype_signature,
            components,
            snapshot_time: event.created_at,
            status_indicators,
        })
    }

    /// Extract relationship history from chronicle events
    async fn extract_relationship_history(
        &self,
        entity_a: Uuid,
        entity_b: Uuid,
        events: &[ChronicleEvent],
    ) -> Result<Vec<RelationshipHistoryEntry>, AppError> {
        let mut relationship_history = Vec::new();
        
        for event in events {
            // Check if this event involves both entities
            if let Ok(actors) = event.get_actors() {
                let actor_ids: Vec<Uuid> = actors.iter().map(|a| a.entity_id).collect();
                if actor_ids.contains(&entity_a) && actor_ids.contains(&entity_b) {
                    // Look for relationship changes in event data
                    if let Some(event_data) = &event.event_data {
                        if let Some(relationship_changes) = event_data.get("relationship_changes") {
                            if let Some(changes_array) = relationship_changes.as_array() {
                                for change in changes_array {
                                    if let Some(change_obj) = change.as_object() {
                                        if let (Some(from_id), Some(to_id)) = (
                                            change_obj.get("from_entity_id").and_then(|v| v.as_str()),
                                            change_obj.get("to_entity_id").and_then(|v| v.as_str())
                                        ) {
                                            let from_uuid = Uuid::parse_str(from_id).ok();
                                            let to_uuid = Uuid::parse_str(to_id).ok();
                                            
                                            // Check if this relationship change involves our entity pair
                                            if let (Some(from), Some(to)) = (from_uuid, to_uuid) {
                                                if (from == entity_a && to == entity_b) || 
                                                   (from == entity_b && to == entity_a) {
                                                    let relationship_type = change_obj.get("relationship_type")
                                                        .and_then(|v| v.as_str())
                                                        .unwrap_or("unknown").to_string();
                                                    
                                                    let relationship_data = change_obj.get("relationship_data")
                                                        .cloned()
                                                        .unwrap_or(serde_json::Value::Null);
                                                    
                                                    relationship_history.push(RelationshipHistoryEntry {
                                                        timestamp: event.created_at,
                                                        triggering_event: Some(event.id),
                                                        relationship_type,
                                                        relationship_data,
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Also check for implicit relationship changes through interactions
                        if let Some(interaction_type) = event_data.get("interaction_type").and_then(|v| v.as_str()) {
                            // Infer relationship implications from interaction types
                            let inferred_relationship = match interaction_type {
                                "combat" => Some(("hostile", -0.5)),
                                "trade" => Some(("neutral", 0.2)),
                                "dialogue" => Some(("acquaintance", 0.1)),
                                "alliance" => Some(("allied", 0.8)),
                                "betrayal" => Some(("hostile", -0.8)),
                                _ => None,
                            };
                            
                            if let Some((rel_type, strength)) = inferred_relationship {
                                let mut relationship_data = serde_json::Map::new();
                                relationship_data.insert("inferred_strength".to_string(), 
                                    serde_json::Value::Number(serde_json::Number::from_f64(strength).unwrap())
                                );
                                relationship_data.insert("interaction_type".to_string(), 
                                    serde_json::Value::String(interaction_type.to_string())
                                );
                                
                                relationship_history.push(RelationshipHistoryEntry {
                                    timestamp: event.created_at,
                                    triggering_event: Some(event.id),
                                    relationship_type: rel_type.to_string(),
                                    relationship_data: serde_json::Value::Object(relationship_data),
                                });
                            }
                        }
                    }
                }
            }
        }
        
        // Sort by timestamp
        relationship_history.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(relationship_history)
    }

    /// Calculate relationship metrics from current state and history
    async fn calculate_relationship_metrics(
        &self,
        current_relationship: &Option<RelationshipContext>,
        relationship_history: &[RelationshipHistoryEntry],
        events: &[ChronicleEvent],
    ) -> Result<RelationshipMetrics, AppError> {
        let mut stability = 0.5;
        let mut strength = 0.0;
        let mut trend = RelationshipTrend::Unknown;
        let interaction_count = relationship_history.len();
        
        // Calculate current strength from current relationship
        if let Some(current) = current_relationship {
            strength = self.extract_relationship_strength(&current.relationship_data);
        }
        
        // Calculate stability based on relationship history
        if relationship_history.len() >= 2 {
            stability = self.calculate_relationship_stability(relationship_history);
        }
        
        // Calculate trend based on recent history
        if relationship_history.len() >= 3 {
            trend = self.calculate_relationship_trend(relationship_history);
        }
        
        // Adjust metrics based on interaction frequency
        let interaction_frequency = self.calculate_interaction_frequency(events).await?;
        if interaction_frequency > 0.8 {
            // High interaction frequency can increase stability
            stability = (stability + 0.1).min(1.0);
        }
        
        Ok(RelationshipMetrics {
            stability,
            strength,
            trend,
            interaction_count,
        })
    }

    /// Extract relationship strength from relationship data
    fn extract_relationship_strength(&self, relationship_data: &serde_json::Value) -> f32 {
        // Look for various strength indicators
        if let Some(strength) = relationship_data.get("strength").and_then(|v| v.as_f64()) {
            return strength as f32;
        }
        
        if let Some(trust) = relationship_data.get("trust").and_then(|v| v.as_f64()) {
            return trust as f32;
        }
        
        if let Some(affection) = relationship_data.get("affection").and_then(|v| v.as_f64()) {
            return affection as f32;
        }
        
        if let Some(valence) = relationship_data.get("valence").and_then(|v| v.as_f64()) {
            return (valence / 100.0) as f32; // Assuming valence is -100 to 100
        }
        
        if let Some(inferred_strength) = relationship_data.get("inferred_strength").and_then(|v| v.as_f64()) {
            return inferred_strength as f32;
        }
        
        // Default neutral strength
        0.5
    }

    /// Calculate relationship stability based on history
    fn calculate_relationship_stability(&self, history: &[RelationshipHistoryEntry]) -> f32 {
        if history.len() < 2 {
            return 0.5;
        }
        
        let mut strength_changes = Vec::new();
        let mut previous_strength = 0.5;
        
        for entry in history {
            let current_strength = self.extract_relationship_strength(&entry.relationship_data);
            let change = (current_strength - previous_strength).abs();
            strength_changes.push(change);
            previous_strength = current_strength;
        }
        
        // Calculate variance of changes
        let mean_change: f32 = strength_changes.iter().sum::<f32>() / strength_changes.len() as f32;
        let variance: f32 = strength_changes.iter()
            .map(|change| (change - mean_change).powi(2))
            .sum::<f32>() / strength_changes.len() as f32;
        
        // Lower variance means higher stability
        (1.0 - variance.sqrt()).max(0.0)
    }

    /// Calculate relationship trend based on recent history
    fn calculate_relationship_trend(&self, history: &[RelationshipHistoryEntry]) -> RelationshipTrend {
        if history.len() < 3 {
            return RelationshipTrend::Unknown;
        }
        
        // Look at the last 3 entries to determine trend
        let recent_entries = &history[history.len().saturating_sub(3)..];
        let mut strengths = Vec::new();
        
        for entry in recent_entries {
            strengths.push(self.extract_relationship_strength(&entry.relationship_data));
        }
        
        // Calculate trend direction
        let first_strength = strengths[0];
        let last_strength = strengths[strengths.len() - 1];
        let overall_change = last_strength - first_strength;
        
        // Calculate volatility
        let mut changes = Vec::new();
        for i in 1..strengths.len() {
            changes.push((strengths[i] - strengths[i-1]).abs());
        }
        let volatility: f32 = changes.iter().sum::<f32>() / changes.len() as f32;
        
        // Determine trend
        if volatility > 0.3 {
            RelationshipTrend::Volatile
        } else if overall_change > 0.1 {
            RelationshipTrend::Improving
        } else if overall_change < -0.1 {
            RelationshipTrend::Declining
        } else {
            RelationshipTrend::Stable
        }
    }

    /// Calculate interaction frequency from events
    async fn calculate_interaction_frequency(&self, events: &[ChronicleEvent]) -> Result<f32, AppError> {
        if events.is_empty() {
            return Ok(0.0);
        }
        
        // Calculate frequency based on event distribution over time
        let first_event = events.first().unwrap();
        let last_event = events.last().unwrap();
        
        let time_span = last_event.created_at - first_event.created_at;
        let days_span = time_span.num_days() as f32;
        
        if days_span <= 0.0 {
            return Ok(1.0); // All events in one day = high frequency
        }
        
        let frequency = events.len() as f32 / days_span;
        
        // Normalize frequency to 0.0-1.0 range
        // Assume 1 interaction per day = 1.0 frequency
        Ok(frequency.min(1.0))
    }

    /// Get user ID from events (helper method)
    fn get_user_id_from_events(&self, events: &[ChronicleEvent]) -> Option<Uuid> {
        events.first().map(|event| event.user_id)
    }

    /// Identify key turning points in relationship history
    fn identify_relationship_turning_points(&self, history: &[RelationshipHistoryEntry]) -> Vec<RelationshipTurningPoint> {
        if history.len() < 2 {
            return Vec::new();
        }
        
        let mut turning_points = Vec::new();
        let mut previous_strength = 0.5;
        
        for (i, entry) in history.iter().enumerate() {
            let current_strength = self.extract_relationship_strength(&entry.relationship_data);
            let strength_change = current_strength - previous_strength;
            
            // Consider a turning point if the change is significant (>0.2)
            if strength_change.abs() > 0.2 {
                turning_points.push(RelationshipTurningPoint {
                    timestamp: entry.timestamp,
                    relationship_type: entry.relationship_type.clone(),
                    strength_change,
                    triggering_event: entry.triggering_event,
                    significance: strength_change.abs(), // Use absolute change as significance
                });
            }
            
            previous_strength = current_strength;
        }
        
        // Sort by significance (most significant first)
        turning_points.sort_by(|a, b| b.significance.partial_cmp(&a.significance).unwrap());
        
        turning_points
    }
}

/// Represents a significant turning point in a relationship
#[derive(Debug, Clone)]
pub struct RelationshipTurningPoint {
    /// When the turning point occurred
    pub timestamp: DateTime<Utc>,
    /// The relationship type at this point
    pub relationship_type: String,
    /// The strength change that occurred
    pub strength_change: f32,
    /// The event that triggered this change
    pub triggering_event: Option<Uuid>,
    /// The significance of this turning point (0.0-1.0)
    pub significance: f32,
}