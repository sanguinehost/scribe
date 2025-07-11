//! ECS-Enhanced RAG Service
//!
//! This service implements Phase 4.2.1 of the ECS Architecture Plan:
//! - Augment chronicle search with current entity state
//! - Provide entity relationship context for RAG
//! - Add "current state" information to chronicle events
//! - Maintain existing chronicle RAG as fallback
//!
//! Key Features:
//! - Hybrid RAG combining chronicle events + ECS state
//! - Toggle-able enhancement via feature flags
//! - Graceful fallback to chronicle-only RAG
//! - Rich entity context for narrative understanding
//! - Current state overlay on historical events

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue};
use tracing::{info, warn, debug, instrument};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

use crate::{
    PgPool,
    config::NarrativeFeatureFlags,
    errors::AppError,
    models::chronicle_event::ChronicleEvent,
    services::{
        ecs_entity_manager::EcsEntityManager,
        ecs_graceful_degradation::EcsGracefulDegradation,
        embeddings::service::EmbeddingPipelineService,
    },
};

/// Configuration for ECS-enhanced RAG behavior
#[derive(Debug, Clone)]
pub struct EcsEnhancedRagConfig {
    /// Enable ECS context enhancement for RAG results
    pub enable_ecs_context_enhancement: bool,
    /// Enable current state overlay on historical events
    pub enable_current_state_overlay: bool,
    /// Enable relationship context in RAG results
    pub enable_relationship_context: bool,
    /// Maximum number of related entities to include
    pub max_related_entities: usize,
    /// Maximum depth for relationship traversal
    pub max_relationship_depth: u32,
    /// Enable entity state caching for performance
    pub enable_entity_state_caching: bool,
    /// Cache TTL for entity states (seconds)
    pub entity_state_cache_ttl: u64,
}

impl Default for EcsEnhancedRagConfig {
    fn default() -> Self {
        Self {
            enable_ecs_context_enhancement: true,
            enable_current_state_overlay: true,
            enable_relationship_context: true,
            max_related_entities: 50,
            max_relationship_depth: 3,
            enable_entity_state_caching: true,
            entity_state_cache_ttl: 300, // 5 minutes
        }
    }
}

/// Enhanced RAG query parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedRagQuery {
    /// Original query text
    pub query: String,
    /// User ID for scoping
    pub user_id: Uuid,
    /// Chronicle ID to focus on (optional)
    pub chronicle_id: Option<Uuid>,
    /// Number of chronicle events to retrieve
    pub max_chronicle_results: usize,
    /// Whether to include current entity states
    pub include_current_state: bool,
    /// Whether to include relationship context
    pub include_relationships: bool,
    /// Specific entity IDs to focus on (optional)
    pub focus_entity_ids: Option<Vec<Uuid>>,
    /// Semantic similarity threshold for chronicle events
    pub similarity_threshold: f32,
}

/// Enhanced RAG result with ECS context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedRagResult {
    /// Query that was executed
    pub query: String,
    /// User ID for scoping
    pub user_id: Uuid,
    /// Chronicle events with enhanced context
    pub chronicle_events: Vec<EnhancedChronicleEvent>,
    /// Current entity states relevant to the query
    pub current_entity_states: Vec<EntityStateContext>,
    /// Relationship context for entities
    pub relationship_context: Vec<RelationshipContext>,
    /// Whether ECS enhancement was applied
    pub ecs_enhanced: bool,
    /// Whether fallback to chronicle-only was used
    pub fallback_used: bool,
    /// Performance metrics
    pub query_duration_ms: u64,
    /// Warnings or issues encountered
    pub warnings: Vec<String>,
}

/// Chronicle event enhanced with current ECS state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedChronicleEvent {
    /// Original chronicle event
    pub event: ChronicleEvent,
    /// Current states of entities mentioned in the event
    pub entity_current_states: HashMap<Uuid, EntityStateSnapshot>,
    /// Relationships between entities at query time
    pub current_relationships: Vec<RelationshipSnapshot>,
    /// Semantic similarity score to query
    pub similarity_score: f32,
    /// Context relevance score
    pub relevance_score: f32,
}

/// Current state snapshot of an entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityStateSnapshot {
    /// Entity ID
    pub entity_id: Uuid,
    /// Entity archetype signature
    pub archetype_signature: String,
    /// All components for this entity
    pub components: HashMap<String, JsonValue>,
    /// When this snapshot was taken
    pub snapshot_time: DateTime<Utc>,
    /// Health/status indicators
    pub status_indicators: Vec<String>,
}

/// Current state context for an entity relevant to the query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityStateContext {
    /// Entity ID
    pub entity_id: Uuid,
    /// Entity name or identifier
    pub entity_name: Option<String>,
    /// Current location or position
    pub current_location: Option<JsonValue>,
    /// Key attributes relevant to the query
    pub key_attributes: HashMap<String, JsonValue>,
    /// Recent changes or updates
    pub recent_changes: Vec<String>,
    /// Query relevance score
    pub relevance_score: f32,
}

/// Relationship context between entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipContext {
    /// Source entity ID
    pub from_entity_id: Uuid,
    /// Target entity ID
    pub to_entity_id: Uuid,
    /// Relationship type
    pub relationship_type: String,
    /// Relationship strength/data
    pub relationship_data: JsonValue,
    /// When this relationship was established
    pub established_at: Option<DateTime<Utc>>,
    /// Last update to this relationship
    pub last_updated: Option<DateTime<Utc>>,
}

/// Snapshot of a relationship at query time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipSnapshot {
    /// Source entity ID
    pub from_entity_id: Uuid,
    /// Target entity ID  
    pub to_entity_id: Uuid,
    /// Relationship type
    pub relationship_type: String,
    /// Relationship data/strength
    pub relationship_data: JsonValue,
    /// How this relationship has changed since the event
    pub change_since_event: Option<String>,
}

/// ECS-Enhanced RAG Service
///
/// This service combines traditional chronicle-based RAG with current ECS entity states
/// to provide richer, more contextual narrative intelligence. It maintains backward
/// compatibility by falling back to chronicle-only RAG when ECS is unavailable.
pub struct EcsEnhancedRagService {
    /// Database connection pool
    db_pool: Arc<PgPool>,
    /// Configuration for enhanced RAG behavior
    config: EcsEnhancedRagConfig,
    /// Feature flags for toggle control
    feature_flags: Arc<NarrativeFeatureFlags>,
    /// ECS entity manager for current state queries
    entity_manager: Arc<EcsEntityManager>,
    /// Graceful degradation service for fallback
    degradation_service: Arc<EcsGracefulDegradation>,
    /// Embedding service for semantic search
    embedding_service: Arc<EmbeddingPipelineService>,
}

impl EcsEnhancedRagService {
    /// Create a new ECS-enhanced RAG service
    pub fn new(
        db_pool: Arc<PgPool>,
        config: EcsEnhancedRagConfig,
        feature_flags: Arc<NarrativeFeatureFlags>,
        entity_manager: Arc<EcsEntityManager>,
        degradation_service: Arc<EcsGracefulDegradation>,
        embedding_service: Arc<EmbeddingPipelineService>,
    ) -> Self {
        Self {
            db_pool,
            config,
            feature_flags,
            entity_manager,
            degradation_service,
            embedding_service,
        }
    }

    /// Execute an enhanced RAG query combining chronicle events with ECS state
    #[instrument(skip(self), fields(user_id = %query.user_id))]
    pub async fn query_enhanced_rag(&self, query: EnhancedRagQuery) -> Result<EnhancedRagResult, AppError> {
        let start_time = std::time::Instant::now();
        
        info!(
            query = %query.query,
            user_id = %query.user_id,
            chronicle_id = ?query.chronicle_id,
            "Starting enhanced RAG query"
        );

        // Execute with graceful degradation
        let result = self.degradation_service.execute_with_fallback(
            "enhanced_rag_query",
            self.execute_enhanced_rag_query(&query),
            self.execute_fallback_rag_query(&query),
        ).await;

        let query_duration_ms = start_time.elapsed().as_millis() as u64;

        match result.result {
            Ok(mut rag_result) => {
                rag_result.query_duration_ms = query_duration_ms;
                rag_result.ecs_enhanced = result.served_from_ecs;
                rag_result.fallback_used = result.fallback_occurred;
                rag_result.warnings.extend(result.warnings);

                info!(
                    query = %query.query,
                    user_id = %query.user_id,
                    ecs_enhanced = rag_result.ecs_enhanced,
                    fallback_used = rag_result.fallback_used,
                    events_count = rag_result.chronicle_events.len(),
                    entities_count = rag_result.current_entity_states.len(),
                    duration_ms = query_duration_ms,
                    "Enhanced RAG query completed"
                );

                Ok(rag_result)
            }
            Err(e) => {
                warn!(
                    query = %query.query,
                    user_id = %query.user_id,
                    error = %e,
                    duration_ms = query_duration_ms,
                    "Enhanced RAG query failed"
                );
                Err(e)
            }
        }
    }

    /// Execute the full enhanced RAG query with ECS integration
    async fn execute_enhanced_rag_query(&self, query: &EnhancedRagQuery) -> Result<EnhancedRagResult, AppError> {
        debug!("Executing enhanced RAG query with ECS integration");

        // Step 1: Execute semantic search on chronicle events
        let chronicle_events = self.search_chronicle_events(query).await?;
        
        // Step 2: Extract entities mentioned in the events
        let entity_ids = self.extract_entity_ids_from_events(&chronicle_events).await?;
        
        // Step 3: Get current states for all relevant entities
        let current_entity_states = if query.include_current_state {
            self.get_current_entity_states(&entity_ids, query.user_id).await?
        } else {
            Vec::new()
        };
        
        // Step 4: Get relationship context if requested
        let relationship_context = if query.include_relationships {
            self.get_relationship_context(&entity_ids, query.user_id).await?
        } else {
            Vec::new()
        };
        
        // Step 5: Enhance chronicle events with current state
        let enhanced_events = self.enhance_chronicle_events_with_state(
            chronicle_events,
            &current_entity_states,
            &relationship_context,
            query
        ).await?;

        Ok(EnhancedRagResult {
            query: query.query.clone(),
            user_id: query.user_id,
            chronicle_events: enhanced_events,
            current_entity_states: self.convert_to_entity_context(&current_entity_states, query).await?,
            relationship_context,
            ecs_enhanced: true,
            fallback_used: false,
            query_duration_ms: 0, // Will be set by caller
            warnings: Vec::new(),
        })
    }

    /// Execute fallback RAG query using only chronicle data
    async fn execute_fallback_rag_query(&self, query: &EnhancedRagQuery) -> Result<EnhancedRagResult, AppError> {
        debug!("Executing fallback RAG query (chronicle-only)");

        // Execute basic chronicle search without ECS enhancement
        let chronicle_events = self.search_chronicle_events(query).await?;
        
        // Convert to enhanced format but without ECS data
        let enhanced_events = chronicle_events.into_iter().map(|event| {
            EnhancedChronicleEvent {
                similarity_score: 0.8, // Placeholder
                relevance_score: 0.8,  // Placeholder
                entity_current_states: HashMap::new(),
                current_relationships: Vec::new(),
                event,
            }
        }).collect();

        Ok(EnhancedRagResult {
            query: query.query.clone(),
            user_id: query.user_id,
            chronicle_events: enhanced_events,
            current_entity_states: Vec::new(),
            relationship_context: Vec::new(),
            ecs_enhanced: false,
            fallback_used: true,
            query_duration_ms: 0, // Will be set by caller
            warnings: vec!["ECS unavailable - using chronicle-only RAG".to_string()],
        })
    }

    // Private helper methods

    /// Search chronicle events using semantic similarity
    async fn search_chronicle_events(&self, query: &EnhancedRagQuery) -> Result<Vec<ChronicleEvent>, AppError> {
        // Placeholder implementation - would use embedding service for semantic search
        debug!("Searching chronicle events for query: {}", query.query);
        
        // In real implementation, this would:
        // 1. Generate embedding for query text
        // 2. Search chronicle events by semantic similarity
        // 3. Filter by user_id, chronicle_id, similarity threshold
        // 4. Return top results ordered by relevance
        
        Ok(Vec::new())
    }

    /// Extract entity IDs mentioned in chronicle events
    async fn extract_entity_ids_from_events(&self, events: &[ChronicleEvent]) -> Result<Vec<Uuid>, AppError> {
        let mut entity_ids = Vec::new();
        
        for event in events {
            // Extract entity IDs from event actors/targets
            // This would parse the event.event_data to find entity references
            debug!("Extracting entity IDs from event: {}", event.id);
        }
        
        // Remove duplicates
        entity_ids.sort_unstable();
        entity_ids.dedup();
        
        Ok(entity_ids)
    }

    /// Get current states for specified entities
    async fn get_current_entity_states(&self, entity_ids: &[Uuid], user_id: Uuid) -> Result<Vec<EntityStateSnapshot>, AppError> {
        let mut states = Vec::new();
        
        for entity_id in entity_ids {
            match self.get_entity_state_snapshot(*entity_id, user_id).await {
                Ok(state) => states.push(state),
                Err(e) => {
                    debug!("Failed to get state for entity {}: {}", entity_id, e);
                    // Continue with other entities
                }
            }
        }
        
        Ok(states)
    }

    /// Get a complete state snapshot for a single entity
    async fn get_entity_state_snapshot(&self, entity_id: Uuid, user_id: Uuid) -> Result<EntityStateSnapshot, AppError> {
        // Query ECS for entity and all its components
        debug!("Getting state snapshot for entity: {}", entity_id);
        
        // Placeholder implementation
        Ok(EntityStateSnapshot {
            entity_id,
            archetype_signature: "unknown".to_string(),
            components: HashMap::new(),
            snapshot_time: chrono::Utc::now(),
            status_indicators: Vec::new(),
        })
    }

    /// Get relationship context for specified entities
    async fn get_relationship_context(&self, entity_ids: &[Uuid], user_id: Uuid) -> Result<Vec<RelationshipContext>, AppError> {
        let relationships = Vec::new();
        
        // Query ECS relationships table for connections between these entities
        debug!("Getting relationship context for {} entities", entity_ids.len());
        
        // Placeholder implementation
        Ok(relationships)
    }

    /// Enhance chronicle events with current ECS state context
    async fn enhance_chronicle_events_with_state(
        &self,
        events: Vec<ChronicleEvent>,
        current_states: &[EntityStateSnapshot],
        relationships: &[RelationshipContext],
        query: &EnhancedRagQuery,
    ) -> Result<Vec<EnhancedChronicleEvent>, AppError> {
        let mut enhanced_events = Vec::new();
        
        for event in events {
            let enhanced_event = self.enhance_single_event(event, current_states, relationships, query).await?;
            enhanced_events.push(enhanced_event);
        }
        
        Ok(enhanced_events)
    }

    /// Enhance a single chronicle event with current state
    async fn enhance_single_event(
        &self,
        event: ChronicleEvent,
        current_states: &[EntityStateSnapshot],
        relationships: &[RelationshipContext],
        _query: &EnhancedRagQuery,
    ) -> Result<EnhancedChronicleEvent, AppError> {
        // Extract entity IDs from this specific event
        let event_entity_ids = self.extract_entity_ids_from_single_event(&event).await?;
        
        // Build current state map for entities in this event
        let mut entity_current_states = HashMap::new();
        for state in current_states {
            if event_entity_ids.contains(&state.entity_id) {
                entity_current_states.insert(state.entity_id, state.clone());
            }
        }
        
        // Build relationship snapshots for entities in this event
        let current_relationships = self.build_relationship_snapshots(&event_entity_ids, relationships).await?;
        
        Ok(EnhancedChronicleEvent {
            similarity_score: 0.8, // Placeholder - would be computed by semantic search
            relevance_score: 0.8,  // Placeholder - would be computed based on entity relevance
            entity_current_states,
            current_relationships,
            event,
        })
    }

    /// Extract entity IDs from a single chronicle event
    async fn extract_entity_ids_from_single_event(&self, event: &ChronicleEvent) -> Result<Vec<Uuid>, AppError> {
        // Parse event.event_data to find entity references
        debug!("Extracting entity IDs from single event: {}", event.id);
        
        // Placeholder implementation
        Ok(Vec::new())
    }

    /// Build relationship snapshots for specific entities
    async fn build_relationship_snapshots(
        &self,
        entity_ids: &[Uuid],
        relationships: &[RelationshipContext],
    ) -> Result<Vec<RelationshipSnapshot>, AppError> {
        let mut snapshots = Vec::new();
        
        for relationship in relationships {
            if entity_ids.contains(&relationship.from_entity_id) || entity_ids.contains(&relationship.to_entity_id) {
                snapshots.push(RelationshipSnapshot {
                    from_entity_id: relationship.from_entity_id,
                    to_entity_id: relationship.to_entity_id,
                    relationship_type: relationship.relationship_type.clone(),
                    relationship_data: relationship.relationship_data.clone(),
                    change_since_event: None, // Could compute difference from event time
                });
            }
        }
        
        Ok(snapshots)
    }

    /// Convert entity state snapshots to query-relevant context
    async fn convert_to_entity_context(
        &self,
        states: &[EntityStateSnapshot],
        query: &EnhancedRagQuery,
    ) -> Result<Vec<EntityStateContext>, AppError> {
        let mut contexts = Vec::new();
        
        for state in states {
            // Extract key attributes relevant to the query
            let key_attributes = self.extract_relevant_attributes(state, &query.query).await?;
            
            contexts.push(EntityStateContext {
                entity_id: state.entity_id,
                entity_name: self.extract_entity_name(state).await?,
                current_location: self.extract_location(state).await?,
                key_attributes,
                recent_changes: Vec::new(), // Could track recent component updates
                relevance_score: 0.8, // Placeholder
            });
        }
        
        Ok(contexts)
    }

    /// Extract attributes relevant to the query from entity state
    async fn extract_relevant_attributes(&self, _state: &EntityStateSnapshot, _query: &str) -> Result<HashMap<String, JsonValue>, AppError> {
        // Analyze query to determine which components/attributes are relevant
        // Return subset of entity components that match query intent
        Ok(HashMap::new())
    }

    /// Extract entity name from state snapshot
    async fn extract_entity_name(&self, _state: &EntityStateSnapshot) -> Result<Option<String>, AppError> {
        // Look for name/identifier component in entity state
        Ok(None)
    }

    /// Extract location from entity state
    async fn extract_location(&self, _state: &EntityStateSnapshot) -> Result<Option<JsonValue>, AppError> {
        // Look for position/location component in entity state
        Ok(None)
    }
}