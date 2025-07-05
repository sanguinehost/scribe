// World Model Service for Phase 2: Query Engine Enhancement
//
// This service generates comprehensive world state snapshots that combine
// chronicle events with current ECS entity states to provide rich context
// for LLM reasoning and advanced narrative queries.

use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use serde_json::{Value as JsonValue};
use tracing::{info, debug, warn, error, instrument};

use crate::{
    PgPool,
    errors::AppError,
    models::{
        world_model::*,
        chronicle_event::ChronicleEvent,
        ecs_diesel::{EcsEntity, EcsComponent, EcsEntityRelationship},
        ecs::{CausalComponent, RelationshipCategory},
    },
    services::{
        ecs_entity_manager::EcsEntityManager,
        hybrid_query_service::HybridQueryService,
        chronicle_service::ChronicleService,
    },
    schema::{ecs_entities, ecs_components, ecs_entity_relationships, chronicle_events},
};
use diesel::prelude::*;

/// Service for generating world model snapshots and LLM contexts
pub struct WorldModelService {
    db_pool: Arc<PgPool>,
    entity_manager: Arc<EcsEntityManager>,
    query_service: Arc<HybridQueryService>,
    chronicle_service: Arc<ChronicleService>,
}

impl WorldModelService {
    /// Create a new world model service
    pub fn new(
        db_pool: Arc<PgPool>,
        entity_manager: Arc<EcsEntityManager>,
        query_service: Arc<HybridQueryService>,
        chronicle_service: Arc<ChronicleService>,
    ) -> Self {
        Self {
            db_pool,
            entity_manager,
            query_service,
            chronicle_service,
        }
    }

    /// Generate a comprehensive world state snapshot
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn generate_world_snapshot(
        &self,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        timestamp: Option<DateTime<Utc>>,
        options: WorldModelOptions,
    ) -> Result<WorldModelSnapshot, AppError> {
        let snapshot_time = timestamp.unwrap_or_else(Utc::now);
        
        info!("Generating world snapshot for user {} at {}", user_id, snapshot_time);
        
        // Step 1: Get all entities (or focused subset)
        let entities = self.gather_entities(user_id, &options).await?;
        debug!("Gathered {} entities", entities.len());
        
        // Step 2: Get active relationships
        let relationships = self.gather_relationships(user_id, &entities).await?;
        debug!("Gathered {} relationships", relationships.len());
        
        // Step 3: Get recent causal events
        let recent_events = self.gather_recent_events(
            user_id, 
            chronicle_id, 
            snapshot_time, 
            options.time_window
        ).await?;
        debug!("Gathered {} recent events", recent_events.len());
        
        // Step 4: Build spatial hierarchy
        let spatial_hierarchy = self.build_spatial_hierarchy(user_id, &entities).await?;
        debug!("Built spatial hierarchy with {} root locations", spatial_hierarchy.root_locations.len());
        
        // Step 5: Create temporal context
        let temporal_context = TemporalContext {
            current_time: snapshot_time,
            time_window: options.time_window,
            significant_moments: self.identify_significant_moments(&recent_events),
        };
        
        let snapshot = WorldModelSnapshot {
            snapshot_id: Uuid::new_v4(),
            user_id,
            chronicle_id,
            timestamp: snapshot_time,
            entities,
            active_relationships: relationships,
            recent_events,
            spatial_hierarchy,
            temporal_context,
        };
        
        info!("Generated world snapshot {} with {} entities, {} relationships, {} events",
              snapshot.snapshot_id, snapshot.entity_count(), 
              snapshot.relationship_count(), snapshot.event_count());
        
        Ok(snapshot)
    }
    
    /// Convert world snapshot to LLM-optimized format
    pub fn snapshot_to_llm_context(
        &self,
        snapshot: &WorldModelSnapshot,
        focus: LLMContextFocus,
    ) -> Result<LLMWorldContext, AppError> {
        debug!("Converting snapshot to LLM context with focus: {:?}", focus.query_intent);
        
        // Generate entity summaries
        let entity_summaries = self.summarize_entities(&snapshot.entities, &focus)?;
        
        // Build relationship graph
        let relationship_graph = self.build_relationship_graph(&snapshot.active_relationships)?;
        
        // Extract causal chains
        let causal_chains = self.extract_causal_chains(&snapshot.recent_events)?;
        
        // Summarize spatial context
        let spatial_context = self.summarize_spatial_context(&snapshot.spatial_hierarchy)?;
        
        // Identify recent changes
        let recent_changes = self.identify_recent_changes(snapshot)?;
        
        // Generate reasoning hints
        let reasoning_hints = self.generate_reasoning_hints(&focus, &causal_chains)?;
        
        Ok(LLMWorldContext {
            entity_summaries,
            relationship_graph,
            causal_chains,
            spatial_context,
            recent_changes,
            reasoning_hints,
        })
    }

    /// Gather entities based on options
    async fn gather_entities(
        &self,
        user_id: Uuid,
        options: &WorldModelOptions,
    ) -> Result<HashMap<Uuid, EntitySnapshot>, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        // Get entities to include
        let entity_ids = if let Some(focus_entities) = &options.focus_entities {
            focus_entities.clone()
        } else {
            // Get all user's entities (limited by max_entities)
            let entities = conn.interact({
                let user_id = user_id;
                let max_entities = options.max_entities;
                move |conn| {
                    ecs_entities::table
                        .filter(ecs_entities::user_id.eq(user_id))
                        .select(EcsEntity::as_select())
                        .limit(max_entities as i64)
                        .load::<EcsEntity>(conn)
                }
            }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            
            entities.into_iter().map(|e| e.id).collect()
        };
        
        // Build entity snapshots
        let mut entity_snapshots = HashMap::new();
        
        for entity_id in entity_ids {
            if let Ok(snapshot) = self.build_entity_snapshot(entity_id, user_id).await {
                entity_snapshots.insert(entity_id, snapshot);
            }
        }
        
        Ok(entity_snapshots)
    }

    /// Build a snapshot for a single entity
    async fn build_entity_snapshot(
        &self,
        entity_id: Uuid,
        user_id: Uuid,
    ) -> Result<EntitySnapshot, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        // Get entity basic info
        let entity = conn.interact({
            let entity_id = entity_id;
            let user_id = user_id;
            move |conn| {
                ecs_entities::table
                    .filter(ecs_entities::id.eq(entity_id))
                    .filter(ecs_entities::user_id.eq(user_id))
                    .select(EcsEntity::as_select())
                    .first::<EcsEntity>(conn)
                    .optional()
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        
        let entity = entity.ok_or_else(|| AppError::NotFound("Entity not found".to_string()))?;
        
        // Get entity components
        let components = conn.interact({
            let entity_id = entity_id;
            let user_id = user_id;
            move |conn| {
                ecs_components::table
                    .filter(ecs_components::entity_id.eq(entity_id))
                    .filter(ecs_components::user_id.eq(user_id))
                    .select(EcsComponent::as_select())
                    .load::<EcsComponent>(conn)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        
        // Build component map
        let component_map: HashMap<String, JsonValue> = components
            .into_iter()
            .map(|c| (c.component_type, c.component_data))
            .collect();
        
        // Get causal influences (recent events affecting this entity)
        let causal_influences = self.get_entity_causal_influences(entity_id, user_id).await?;
        
        // Extract entity name from components if available
        let entity_name = component_map.get("Name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        
        Ok(EntitySnapshot {
            entity_id,
            archetype: entity.archetype_signature,
            name: entity_name,
            components: component_map,
            last_modified: entity.updated_at,
            causal_influences,
        })
    }

    /// Get recent events that influenced an entity
    async fn get_entity_causal_influences(
        &self,
        entity_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, AppError> {
        // Generate causal component to get influences
        match CausalComponent::generate_for_entity(entity_id, user_id, &self.db_pool).await {
            Ok(causal_component) => {
                let mut influences = causal_component.caused_by_events;
                influences.extend(causal_component.causes_events);
                Ok(influences)
            }
            Err(_) => {
                // If causal component generation fails, return empty influences
                Ok(Vec::new())
            }
        }
    }

    /// Gather relationships between entities
    async fn gather_relationships(
        &self,
        user_id: Uuid,
        entities: &HashMap<Uuid, EntitySnapshot>,
    ) -> Result<Vec<RelationshipSnapshot>, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        let entity_ids: Vec<Uuid> = entities.keys().cloned().collect();
        
        // Get relationships involving these entities
        let relationships = conn.interact({
            let entity_ids = entity_ids.clone();
            let user_id = user_id;
            move |conn| {
                ecs_entity_relationships::table
                    .filter(ecs_entity_relationships::user_id.eq(user_id))
                    .filter(
                        ecs_entity_relationships::from_entity_id.eq_any(&entity_ids)
                        .or(ecs_entity_relationships::to_entity_id.eq_any(&entity_ids))
                    )
                    .select(EcsEntityRelationship::as_select())
                    .load::<EcsEntityRelationship>(conn)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        
        // Convert to relationship snapshots
        let mut snapshots = Vec::new();
        for rel in relationships {
            let snapshot = RelationshipSnapshot {
                from_entity: rel.from_entity_id,
                to_entity: rel.to_entity_id,
                relationship_type: rel.relationship_type,
                category: rel.relationship_category.unwrap_or_else(|| "social".to_string()),
                strength: rel.strength.unwrap_or(0.5) as f32,
                metadata: rel.relationship_data,
                last_updated: rel.updated_at,
            };
            snapshots.push(snapshot);
        }
        
        Ok(snapshots)
    }

    /// Gather recent events within the time window
    async fn gather_recent_events(
        &self,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        snapshot_time: DateTime<Utc>,
        time_window: Duration,
    ) -> Result<Vec<CausalEventSnapshot>, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        
        let start_time = snapshot_time - time_window;
        
        // Build base query
        let mut query = chronicle_events::table
            .filter(chronicle_events::user_id.eq(user_id))
            .filter(chronicle_events::created_at.ge(start_time))
            .filter(chronicle_events::created_at.le(snapshot_time))
            .into_boxed();
        
        // Filter by chronicle if specified
        if let Some(chron_id) = chronicle_id {
            query = query.filter(chronicle_events::chronicle_id.eq(chron_id));
        }
        
        let events = conn.interact({
            let query = query;
            move |conn| {
                query
                    .select(ChronicleEvent::as_select())
                    .order(chronicle_events::created_at.desc())
                    .limit(100) // Limit to most recent 100 events
                    .load::<ChronicleEvent>(conn)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        
        // Convert to causal event snapshots
        let mut causal_events = Vec::new();
        for event in events {
            let mut causal_event = CausalEventSnapshot::new(
                event.id,
                event.event_type.clone(),
                event.created_at,
                event.summary.clone(),
            );
            
            // Extract affected entities from actors if available
            if let Some(actors) = &event.actors {
                if let Ok(actor_list) = event.get_actors() {
                    for actor in actor_list {
                        causal_event.add_affected_entity(actor.entity_id);
                    }
                }
            }
            
            // Add causal relationships
            if let Some(caused_by) = event.caused_by_event_id {
                causal_event.set_caused_by(caused_by);
            }
            
            if let Some(causes) = &event.causes_event_ids {
                for cause in causes {
                    if let Some(cause_id) = cause {
                        causal_event.add_caused_event(*cause_id);
                    }
                }
            }
            
            causal_events.push(causal_event);
        }
        
        Ok(causal_events)
    }

    /// Build spatial hierarchy from entities
    async fn build_spatial_hierarchy(
        &self,
        _user_id: Uuid,
        entities: &HashMap<Uuid, EntitySnapshot>,
    ) -> Result<SpatialHierarchy, AppError> {
        let mut hierarchy = SpatialHierarchy::default();
        
        // Extract spatial information from entity components
        for (entity_id, entity) in entities {
            if let Some(position_data) = entity.get_component("Position") {
                // Try to extract location information
                if let Some(zone) = position_data.get("zone").and_then(|v| v.as_str()) {
                    // For now, treat zone as location
                    // In a more sophisticated implementation, we'd have proper location entities
                    let location_id = Uuid::new_v4(); // Placeholder
                    hierarchy.set_entity_location(*entity_id, location_id);
                }
            }
        }
        
        Ok(hierarchy)
    }

    /// Identify significant moments from events
    fn identify_significant_moments(&self, events: &[CausalEventSnapshot]) -> Vec<DateTime<Utc>> {
        // For now, just return timestamps of causal events
        events.iter()
            .filter(|e| e.is_causal())
            .map(|e| e.timestamp)
            .collect()
    }

    /// Summarize entities for LLM consumption
    fn summarize_entities(
        &self,
        entities: &HashMap<Uuid, EntitySnapshot>,
        focus: &LLMContextFocus,
    ) -> Result<Vec<EntitySummary>, AppError> {
        let mut summaries = Vec::new();
        
        for (entity_id, entity) in entities {
            // Skip entities not relevant to focus if specified
            if !focus.key_entities.is_empty() && !focus.key_entities.contains(entity_id) {
                continue;
            }
            
            let mut summary = EntitySummary::new(
                *entity_id,
                entity.name.clone().unwrap_or_else(|| "Unknown".to_string()),
                entity.archetype.clone(),
                self.describe_entity_current_state(entity),
            );
            
            // Add key attributes from components
            if let Some(health) = entity.get_component("Health") {
                if let (Some(current), Some(max)) = (
                    health.get("current").and_then(|v| v.as_i64()),
                    health.get("max").and_then(|v| v.as_i64())
                ) {
                    summary.add_attribute("health".to_string(), format!("{}/{}", current, max));
                }
            }
            
            if let Some(position) = entity.get_component("Position") {
                if let Some(zone) = position.get("zone").and_then(|v| v.as_str()) {
                    summary.add_attribute("location".to_string(), zone.to_string());
                }
            }
            
            // Add recent actions based on causal influences (simplified)
            for _influence in &entity.causal_influences {
                summary.add_recent_action("Involved in recent event".to_string());
            }
            
            summaries.push(summary);
        }
        
        Ok(summaries)
    }

    /// Describe an entity's current state
    fn describe_entity_current_state(&self, entity: &EntitySnapshot) -> String {
        let mut state_parts = Vec::new();
        
        // Check health
        if let Some(health) = entity.get_component("Health") {
            if let Some(current) = health.get("current").and_then(|v| v.as_i64()) {
                if current <= 0 {
                    state_parts.push("deceased".to_string());
                } else if current < 50 {
                    state_parts.push("injured".to_string());
                } else {
                    state_parts.push("healthy".to_string());
                }
            }
        }
        
        // Check location
        if let Some(position) = entity.get_component("Position") {
            if let Some(zone) = position.get("zone").and_then(|v| v.as_str()) {
                state_parts.push(format!("in {}", zone));
            }
        }
        
        if state_parts.is_empty() {
            "active".to_string()
        } else {
            state_parts.join(", ")
        }
    }

    /// Build relationship graph for LLM
    fn build_relationship_graph(
        &self,
        relationships: &[RelationshipSnapshot],
    ) -> Result<RelationshipGraph, AppError> {
        let mut graph = RelationshipGraph::new();
        
        // Build nodes from unique entities
        let mut entities = std::collections::HashSet::new();
        for rel in relationships {
            entities.insert(rel.from_entity);
            entities.insert(rel.to_entity);
        }
        
        for entity_id in entities {
            let node = GraphNode::new(
                entity_id,
                format!("Entity {}", entity_id),
                "entity".to_string(),
            );
            graph.add_node(node);
        }
        
        // Build edges from relationships
        for rel in relationships {
            let mut edge = GraphEdge::new(
                rel.from_entity,
                rel.to_entity,
                rel.relationship_type.clone(),
                rel.strength,
                format!("{} -> {}", rel.relationship_type, rel.strength),
            );
            edge.add_attribute("category".to_string(), rel.category.clone());
            graph.add_edge(edge);
        }
        
        Ok(graph)
    }

    /// Extract causal chains from events
    fn extract_causal_chains(
        &self,
        events: &[CausalEventSnapshot],
    ) -> Result<Vec<CausalChain>, AppError> {
        let mut chains = Vec::new();
        
        // Simple causal chain extraction
        // Find events that start chains (no caused_by)
        for event in events {
            if event.caused_by.is_none() && !event.causes.is_empty() {
                let mut chain = CausalChain::new(
                    event.summary.clone(),
                    "Multiple effects".to_string(),
                    event.confidence,
                );
                
                // Add the initial step
                let step = CausalStep::new(
                    event.summary.clone(),
                    vec!["Entity".to_string()], // Simplified
                    event.timestamp,
                    event.confidence,
                );
                chain.add_step(step);
                
                chains.push(chain);
            }
        }
        
        Ok(chains)
    }

    /// Summarize spatial context
    fn summarize_spatial_context(
        &self,
        _hierarchy: &SpatialHierarchy,
    ) -> Result<SpatialContext, AppError> {
        // Simplified spatial context for now
        Ok(SpatialContext::new())
    }

    /// Identify recent changes
    fn identify_recent_changes(
        &self,
        snapshot: &WorldModelSnapshot,
    ) -> Result<Vec<RecentChange>, AppError> {
        let mut changes = Vec::new();
        
        // Identify changes from recent events
        for event in &snapshot.recent_events {
            if !event.affected_entities.is_empty() {
                let change = RecentChange::new(
                    "entity_state_change".to_string(),
                    event.affected_entities.first().copied(),
                    format!("Event: {}", event.summary),
                    "medium".to_string(),
                );
                changes.push(change);
            }
        }
        
        Ok(changes)
    }

    /// Generate reasoning hints for LLM
    fn generate_reasoning_hints(
        &self,
        focus: &LLMContextFocus,
        causal_chains: &[CausalChain],
    ) -> Result<Vec<String>, AppError> {
        let mut hints = Vec::new();
        
        // Add query-specific hints
        hints.push(format!("Focus on understanding: {}", focus.query_intent));
        
        // Add causal reasoning hints
        if !causal_chains.is_empty() {
            hints.push("Consider the causal relationships between events".to_string());
            hints.push("Look for patterns in cause-and-effect chains".to_string());
        }
        
        // Add reasoning depth hints
        match focus.reasoning_depth {
            ReasoningDepth::Surface => {
                hints.push("Focus on immediate facts and current state".to_string());
            }
            ReasoningDepth::Causal => {
                hints.push("Analyze cause-and-effect relationships".to_string());
            }
            ReasoningDepth::Deep => {
                hints.push("Consider complex interactions and indirect effects".to_string());
            }
        }
        
        Ok(hints)
    }
}

/// Options for world model generation
#[derive(Debug, Clone)]
pub struct WorldModelOptions {
    pub time_window: Duration,
    pub focus_entities: Option<Vec<Uuid>>,
    pub include_inactive: bool,
    pub max_entities: usize,
}

impl Default for WorldModelOptions {
    fn default() -> Self {
        Self {
            time_window: Duration::hours(24),
            focus_entities: None,
            include_inactive: false,
            max_entities: 100,
        }
    }
}

/// Focus parameters for LLM context generation
#[derive(Debug, Clone)]
pub struct LLMContextFocus {
    pub query_intent: String,
    pub key_entities: Vec<Uuid>,
    pub time_focus: TimeFocus,
    pub reasoning_depth: ReasoningDepth,
}

/// Time focus for LLM context
#[derive(Debug, Clone)]
pub enum TimeFocus {
    Current,
    Historical(Duration),
    Specific(DateTime<Utc>),
}

/// Reasoning depth for LLM context
#[derive(Debug, Clone)]
pub enum ReasoningDepth {
    Surface,  // Just facts
    Causal,   // Include causality
    Deep,     // Full reasoning chains
}