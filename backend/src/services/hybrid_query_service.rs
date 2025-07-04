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
    models::{
        chronicle_event::ChronicleEvent,
        ecs_diesel::{EcsEntity, EcsComponent},
    },
    services::{
        ecs_entity_manager::EcsEntityManager,
        ecs_enhanced_rag_service::{
            EcsEnhancedRagService, EnhancedRagQuery, EnhancedRagResult,
            EntityStateSnapshot, EntityStateContext, RelationshipContext
        },
        ecs_graceful_degradation::EcsGracefulDegradation,
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

/// Hybrid Query Service
///
/// This service provides complex queries that span both chronicle events and current ECS state,
/// enabling narrative intelligence questions like "What happened to X and where are they now?"
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
}

impl HybridQueryService {
    /// Create a new hybrid query service
    pub fn new(
        db_pool: Arc<PgPool>,
        config: HybridQueryConfig,
        feature_flags: Arc<NarrativeFeatureFlags>,
        entity_manager: Arc<EcsEntityManager>,
        rag_service: Arc<EcsEnhancedRagService>,
        degradation_service: Arc<EcsGracefulDegradation>,
    ) -> Self {
        Self {
            db_pool,
            config,
            feature_flags,
            entity_manager,
            rag_service,
            degradation_service,
        }
    }

    /// Execute a hybrid query combining chronicle and ECS data
    #[instrument(skip(self), fields(user_id = %query.user_id))]
    pub async fn execute_hybrid_query(&self, query: HybridQuery) -> Result<HybridQueryResult, AppError> {
        let start_time = std::time::Instant::now();

        info!(
            query_type = ?query.query_type,
            user_id = %query.user_id,
            chronicle_id = ?query.chronicle_id,
            "Starting hybrid query execution"
        );

        // Execute with graceful degradation
        let result = self.degradation_service.execute_with_fallback(
            "hybrid_query",
            self.execute_enhanced_hybrid_query(&query),
            self.execute_fallback_hybrid_query(&query),
        ).await;

        let total_duration_ms = start_time.elapsed().as_millis() as u64;

        match result.result {
            Ok(mut hybrid_result) => {
                hybrid_result.performance.total_duration_ms = total_duration_ms;
                hybrid_result.warnings.extend(result.warnings);

                info!(
                    query_type = ?query.query_type,
                    user_id = %query.user_id,
                    entities_found = hybrid_result.entities.len(),
                    events_analyzed = hybrid_result.chronicle_events.len(),
                    duration_ms = total_duration_ms,
                    "Hybrid query completed successfully"
                );

                Ok(hybrid_result)
            }
            Err(e) => {
                warn!(
                    query_type = ?query.query_type,
                    user_id = %query.user_id,
                    error = %e,
                    duration_ms = total_duration_ms,
                    "Hybrid query failed"
                );
                Err(e)
            }
        }
    }

    /// Execute enhanced hybrid query with full ECS integration
    async fn execute_enhanced_hybrid_query(&self, query: &HybridQuery) -> Result<HybridQueryResult, AppError> {
        debug!("Executing enhanced hybrid query with full ECS integration");

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
                cache_hit_rate: 0.0, // TODO: Implement cache metrics
                db_queries_count: 0, // TODO: Track database queries
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
        
        // Use the enhanced RAG service for semantic search
        let rag_result = self.rag_service.query_enhanced_rag(rag_query).await?;
        
        // Extract chronicle events from the RAG result
        let events = rag_result.chronicle_events
            .into_iter()
            .map(|enhanced_event| enhanced_event.event)
            .collect();

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
        };

        Ok(EnhancedRagQuery {
            query: query_text,
            user_id: query.user_id,
            chronicle_id: query.chronicle_id,
            max_chronicle_results: query.max_results,
            include_current_state: query.include_current_state,
            include_relationships: query.include_relationships,
            focus_entity_ids: None, // TODO: Extract from query if available
            similarity_threshold: query.options.confidence_threshold,
        })
    }

    /// Extract entity IDs relevant to the query
    async fn extract_relevant_entity_ids(&self, query: &HybridQuery, events: &[ChronicleEvent]) -> Result<Vec<Uuid>, AppError> {
        let mut entity_ids = Vec::new();

        // Extract entities from events
        for event in events {
            // TODO: Parse event data to extract entity references
            debug!("Extracting entity IDs from event: {}", event.id);
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
    async fn get_entity_current_state(&self, entity_id: Uuid, user_id: Uuid) -> Result<EntityStateSnapshot, AppError> {
        // TODO: Use entity manager to get current state
        debug!("Getting current state for entity: {}", entity_id);
        
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
    async fn entity_involved_in_event(&self, _entity_id: Uuid, _event: &ChronicleEvent) -> Result<bool, AppError> {
        // TODO: Parse event data to check entity involvement
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
        Ok(Vec::new())
    }

    /// Extract entity name
    async fn extract_entity_name(&self, _entity_id: Uuid) -> Result<Option<String>, AppError> {
        // TODO: Get entity name from ECS components
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
        query: &HybridQuery,
    ) -> Result<Vec<EntityTimelineContext>, AppError> {
        let mut contexts = Vec::new();

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
            _ => {}
        }

        Ok(HybridQuerySummary {
            entities_found: entities.len(),
            events_analyzed: events.len(),
            relationships_found: relationships.len(),
            key_insights,
            narrative_answer: None, // TODO: Generate narrative answer
        })
    }
}