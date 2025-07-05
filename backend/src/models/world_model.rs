// World Model Types for Enhanced Narrative Intelligence
//
// This module provides types for generating comprehensive world state snapshots
// that combine chronicle events with current ECS entity states to provide
// rich context for LLM reasoning and advanced narrative queries.

use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use serde_json::Value as JsonValue;

/// Complete snapshot of the world state at a point in time
/// 
/// This is the primary data structure for providing LLM-ready context
/// that combines chronicle narrative history with current ECS entity states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorldModelSnapshot {
    pub snapshot_id: Uuid,
    pub user_id: Uuid,
    pub chronicle_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub entities: HashMap<Uuid, EntitySnapshot>,
    pub active_relationships: Vec<RelationshipSnapshot>,
    pub recent_events: Vec<CausalEventSnapshot>,
    pub spatial_hierarchy: SpatialHierarchy,
    pub temporal_context: TemporalContext,
}

impl WorldModelSnapshot {
    /// Create a new empty world model snapshot
    pub fn new(user_id: Uuid, chronicle_id: Option<Uuid>) -> Self {
        Self {
            snapshot_id: Uuid::new_v4(),
            user_id,
            chronicle_id,
            timestamp: Utc::now(),
            entities: HashMap::new(),
            active_relationships: Vec::new(),
            recent_events: Vec::new(),
            spatial_hierarchy: SpatialHierarchy::default(),
            temporal_context: TemporalContext::default(),
        }
    }

    /// Get entity count in the snapshot
    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }

    /// Get relationship count in the snapshot
    pub fn relationship_count(&self) -> usize {
        self.active_relationships.len()
    }

    /// Get recent event count in the snapshot
    pub fn event_count(&self) -> usize {
        self.recent_events.len()
    }

    /// Check if an entity exists in the snapshot
    pub fn has_entity(&self, entity_id: &Uuid) -> bool {
        self.entities.contains_key(entity_id)
    }

    /// Get an entity snapshot by ID
    pub fn get_entity(&self, entity_id: &Uuid) -> Option<&EntitySnapshot> {
        self.entities.get(entity_id)
    }

    /// Add an entity to the snapshot
    pub fn add_entity(&mut self, entity: EntitySnapshot) {
        self.entities.insert(entity.entity_id, entity);
    }

    /// Add a relationship to the snapshot
    pub fn add_relationship(&mut self, relationship: RelationshipSnapshot) {
        self.active_relationships.push(relationship);
    }

    /// Add an event to the snapshot
    pub fn add_event(&mut self, event: CausalEventSnapshot) {
        self.recent_events.push(event);
    }
}

/// Snapshot of a single entity's current state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySnapshot {
    pub entity_id: Uuid,
    pub archetype: String,
    pub name: Option<String>,
    pub components: HashMap<String, JsonValue>,
    pub last_modified: DateTime<Utc>,
    pub causal_influences: Vec<Uuid>, // Recent events that affected this entity
}

impl EntitySnapshot {
    /// Create a new entity snapshot
    pub fn new(
        entity_id: Uuid,
        archetype: String,
        name: Option<String>,
    ) -> Self {
        Self {
            entity_id,
            archetype,
            name,
            components: HashMap::new(),
            last_modified: Utc::now(),
            causal_influences: Vec::new(),
        }
    }

    /// Add a component to the entity snapshot
    pub fn add_component(&mut self, component_type: String, data: JsonValue) {
        self.components.insert(component_type, data);
        self.last_modified = Utc::now();
    }

    /// Get a component by type
    pub fn get_component(&self, component_type: &str) -> Option<&JsonValue> {
        self.components.get(component_type)
    }

    /// Check if entity has a specific component
    pub fn has_component(&self, component_type: &str) -> bool {
        self.components.contains_key(component_type)
    }

    /// Add a causal influence event
    pub fn add_causal_influence(&mut self, event_id: Uuid) {
        if !self.causal_influences.contains(&event_id) {
            self.causal_influences.push(event_id);
        }
    }
}

/// Snapshot of a relationship between entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipSnapshot {
    pub from_entity: Uuid,
    pub to_entity: Uuid,
    pub relationship_type: String,
    pub category: String,
    pub strength: f32,
    pub metadata: JsonValue,
    pub last_updated: DateTime<Utc>,
}

impl RelationshipSnapshot {
    /// Create a new relationship snapshot
    pub fn new(
        from_entity: Uuid,
        to_entity: Uuid,
        relationship_type: String,
        category: String,
        strength: f32,
        metadata: JsonValue,
    ) -> Self {
        Self {
            from_entity,
            to_entity,
            relationship_type,
            category,
            strength,
            metadata,
            last_updated: Utc::now(),
        }
    }

    /// Check if this is a causal relationship
    pub fn is_causal(&self) -> bool {
        self.category == "causal" || 
        self.relationship_type == "causes_effect_on" || 
        self.relationship_type == "affected_by"
    }

    /// Check if this relationship involves a specific entity
    pub fn involves_entity(&self, entity_id: &Uuid) -> bool {
        self.from_entity == *entity_id || self.to_entity == *entity_id
    }

    /// Get the other entity in the relationship
    pub fn get_other_entity(&self, entity_id: &Uuid) -> Option<Uuid> {
        if self.from_entity == *entity_id {
            Some(self.to_entity)
        } else if self.to_entity == *entity_id {
            Some(self.from_entity)
        } else {
            None
        }
    }
}

/// Snapshot of a chronicle event with causal information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalEventSnapshot {
    pub event_id: Uuid,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub affected_entities: Vec<Uuid>,
    pub caused_by: Option<Uuid>,
    pub causes: Vec<Uuid>,
    pub summary: String,
    pub confidence: f32,
}

impl CausalEventSnapshot {
    /// Create a new causal event snapshot
    pub fn new(
        event_id: Uuid,
        event_type: String,
        timestamp: DateTime<Utc>,
        summary: String,
    ) -> Self {
        Self {
            event_id,
            event_type,
            timestamp,
            affected_entities: Vec::new(),
            caused_by: None,
            causes: Vec::new(),
            summary,
            confidence: 1.0,
        }
    }

    /// Add an affected entity
    pub fn add_affected_entity(&mut self, entity_id: Uuid) {
        if !self.affected_entities.contains(&entity_id) {
            self.affected_entities.push(entity_id);
        }
    }

    /// Set the causing event
    pub fn set_caused_by(&mut self, event_id: Uuid) {
        self.caused_by = Some(event_id);
    }

    /// Add a caused event
    pub fn add_caused_event(&mut self, event_id: Uuid) {
        if !self.causes.contains(&event_id) {
            self.causes.push(event_id);
        }
    }

    /// Check if this event is part of a causal chain
    pub fn is_causal(&self) -> bool {
        self.caused_by.is_some() || !self.causes.is_empty()
    }

    /// Check if this event affects a specific entity
    pub fn affects_entity(&self, entity_id: &Uuid) -> bool {
        self.affected_entities.contains(entity_id)
    }
}

/// Spatial hierarchy representing containment and location relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialHierarchy {
    pub root_locations: Vec<Uuid>,
    pub containment_tree: HashMap<Uuid, Vec<Uuid>>,
    pub entity_locations: HashMap<Uuid, Uuid>,
}

impl Default for SpatialHierarchy {
    fn default() -> Self {
        Self {
            root_locations: Vec::new(),
            containment_tree: HashMap::new(),
            entity_locations: HashMap::new(),
        }
    }
}

impl SpatialHierarchy {
    /// Add a root location
    pub fn add_root_location(&mut self, location_id: Uuid) {
        if !self.root_locations.contains(&location_id) {
            self.root_locations.push(location_id);
        }
    }

    /// Add a containment relationship (parent contains child)
    pub fn add_containment(&mut self, parent: Uuid, child: Uuid) {
        self.containment_tree
            .entry(parent)
            .or_insert_with(Vec::new)
            .push(child);
    }

    /// Set entity location
    pub fn set_entity_location(&mut self, entity_id: Uuid, location_id: Uuid) {
        self.entity_locations.insert(entity_id, location_id);
    }

    /// Get entity location
    pub fn get_entity_location(&self, entity_id: &Uuid) -> Option<&Uuid> {
        self.entity_locations.get(entity_id)
    }

    /// Get entities at a location
    pub fn get_entities_at_location(&self, location_id: &Uuid) -> Vec<Uuid> {
        self.entity_locations
            .iter()
            .filter(|(_, loc)| *loc == location_id)
            .map(|(entity, _)| *entity)
            .collect()
    }

    /// Get children of a location
    pub fn get_children(&self, location_id: &Uuid) -> Option<&Vec<Uuid>> {
        self.containment_tree.get(location_id)
    }
}

/// Temporal context for the world snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalContext {
    pub current_time: DateTime<Utc>,
    pub time_window: Duration,
    pub significant_moments: Vec<DateTime<Utc>>,
}

impl Default for TemporalContext {
    fn default() -> Self {
        Self {
            current_time: Utc::now(),
            time_window: Duration::hours(24),
            significant_moments: Vec::new(),
        }
    }
}

impl TemporalContext {
    /// Create a new temporal context
    pub fn new(time_window: Duration) -> Self {
        Self {
            current_time: Utc::now(),
            time_window,
            significant_moments: Vec::new(),
        }
    }

    /// Add a significant moment
    pub fn add_significant_moment(&mut self, moment: DateTime<Utc>) {
        if !self.significant_moments.contains(&moment) {
            self.significant_moments.push(moment);
        }
    }

    /// Check if a timestamp is within the time window
    pub fn is_within_window(&self, timestamp: &DateTime<Utc>) -> bool {
        let start_time = self.current_time - self.time_window;
        timestamp >= &start_time && timestamp <= &self.current_time
    }

    /// Get the start of the time window
    pub fn window_start(&self) -> DateTime<Utc> {
        self.current_time - self.time_window
    }
}

/// LLM-optimized world context for reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMWorldContext {
    pub entity_summaries: Vec<EntitySummary>,
    pub relationship_graph: RelationshipGraph,
    pub causal_chains: Vec<CausalChain>,
    pub spatial_context: SpatialContext,
    pub recent_changes: Vec<RecentChange>,
    pub reasoning_hints: Vec<String>,
}

impl LLMWorldContext {
    /// Create a new empty LLM world context
    pub fn new() -> Self {
        Self {
            entity_summaries: Vec::new(),
            relationship_graph: RelationshipGraph::new(),
            causal_chains: Vec::new(),
            spatial_context: SpatialContext::new(),
            recent_changes: Vec::new(),
            reasoning_hints: Vec::new(),
        }
    }

    /// Add an entity summary
    pub fn add_entity_summary(&mut self, summary: EntitySummary) {
        self.entity_summaries.push(summary);
    }

    /// Add a causal chain
    pub fn add_causal_chain(&mut self, chain: CausalChain) {
        self.causal_chains.push(chain);
    }

    /// Add a recent change
    pub fn add_recent_change(&mut self, change: RecentChange) {
        self.recent_changes.push(change);
    }

    /// Add a reasoning hint
    pub fn add_reasoning_hint(&mut self, hint: String) {
        self.reasoning_hints.push(hint);
    }
}

/// Summary of an entity for LLM consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySummary {
    pub entity_id: Uuid,
    pub name: String,
    pub entity_type: String,
    pub current_state: String,
    pub key_attributes: HashMap<String, String>,
    pub recent_actions: Vec<String>,
}

impl EntitySummary {
    /// Create a new entity summary
    pub fn new(
        entity_id: Uuid,
        name: String,
        entity_type: String,
        current_state: String,
    ) -> Self {
        Self {
            entity_id,
            name,
            entity_type,
            current_state,
            key_attributes: HashMap::new(),
            recent_actions: Vec::new(),
        }
    }

    /// Add a key attribute
    pub fn add_attribute(&mut self, key: String, value: String) {
        self.key_attributes.insert(key, value);
    }

    /// Add a recent action
    pub fn add_recent_action(&mut self, action: String) {
        self.recent_actions.push(action);
    }
}

/// Graph representation of relationships for LLM reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub clusters: Vec<RelationshipCluster>,
}

impl RelationshipGraph {
    /// Create a new empty relationship graph
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            clusters: Vec::new(),
        }
    }

    /// Add a node to the graph
    pub fn add_node(&mut self, node: GraphNode) {
        self.nodes.push(node);
    }

    /// Add an edge to the graph
    pub fn add_edge(&mut self, edge: GraphEdge) {
        self.edges.push(edge);
    }

    /// Add a cluster to the graph
    pub fn add_cluster(&mut self, cluster: RelationshipCluster) {
        self.clusters.push(cluster);
    }

    /// Find a node by entity ID
    pub fn find_node(&self, entity_id: &Uuid) -> Option<&GraphNode> {
        self.nodes.iter().find(|n| n.entity_id == *entity_id)
    }

    /// Get edges involving a specific entity
    pub fn get_entity_edges(&self, entity_id: &Uuid) -> Vec<&GraphEdge> {
        self.edges
            .iter()
            .filter(|e| e.from_entity == *entity_id || e.to_entity == *entity_id)
            .collect()
    }
}

/// Node in the relationship graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub entity_id: Uuid,
    pub label: String,
    pub node_type: String,
    pub attributes: HashMap<String, String>,
}

impl GraphNode {
    /// Create a new graph node
    pub fn new(entity_id: Uuid, label: String, node_type: String) -> Self {
        Self {
            entity_id,
            label,
            node_type,
            attributes: HashMap::new(),
        }
    }

    /// Add an attribute to the node
    pub fn add_attribute(&mut self, key: String, value: String) {
        self.attributes.insert(key, value);
    }
}

/// Edge in the relationship graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from_entity: Uuid,
    pub to_entity: Uuid,
    pub relationship_type: String,
    pub strength: f32,
    pub label: String,
    pub attributes: HashMap<String, String>,
}

impl GraphEdge {
    /// Create a new graph edge
    pub fn new(
        from_entity: Uuid,
        to_entity: Uuid,
        relationship_type: String,
        strength: f32,
        label: String,
    ) -> Self {
        Self {
            from_entity,
            to_entity,
            relationship_type,
            strength,
            label,
            attributes: HashMap::new(),
        }
    }

    /// Add an attribute to the edge
    pub fn add_attribute(&mut self, key: String, value: String) {
        self.attributes.insert(key, value);
    }
}

/// Cluster of related entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipCluster {
    pub cluster_id: Uuid,
    pub cluster_type: String,
    pub entities: Vec<Uuid>,
    pub description: String,
    pub strength: f32,
}

impl RelationshipCluster {
    /// Create a new relationship cluster
    pub fn new(
        cluster_type: String,
        entities: Vec<Uuid>,
        description: String,
        strength: f32,
    ) -> Self {
        Self {
            cluster_id: Uuid::new_v4(),
            cluster_type,
            entities,
            description,
            strength,
        }
    }

    /// Check if cluster contains an entity
    pub fn contains_entity(&self, entity_id: &Uuid) -> bool {
        self.entities.contains(entity_id)
    }

    /// Add an entity to the cluster
    pub fn add_entity(&mut self, entity_id: Uuid) {
        if !self.contains_entity(&entity_id) {
            self.entities.push(entity_id);
        }
    }
}

/// Causal chain for reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalChain {
    pub chain_id: Uuid,
    pub root_cause: String,
    pub steps: Vec<CausalStep>,
    pub final_effect: String,
    pub confidence: f32,
}

impl CausalChain {
    /// Create a new causal chain
    pub fn new(root_cause: String, final_effect: String, confidence: f32) -> Self {
        Self {
            chain_id: Uuid::new_v4(),
            root_cause,
            steps: Vec::new(),
            final_effect,
            confidence,
        }
    }

    /// Add a step to the causal chain
    pub fn add_step(&mut self, step: CausalStep) {
        self.steps.push(step);
    }

    /// Get the chain length
    pub fn length(&self) -> usize {
        self.steps.len()
    }
}

/// Step in a causal chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalStep {
    pub event: String,
    pub entities_involved: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub confidence: f32,
}

impl CausalStep {
    /// Create a new causal step
    pub fn new(
        event: String,
        entities_involved: Vec<String>,
        timestamp: DateTime<Utc>,
        confidence: f32,
    ) -> Self {
        Self {
            event,
            entities_involved,
            timestamp,
            confidence,
        }
    }
}

/// Spatial context for LLM reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialContext {
    pub locations: Vec<LocationSummary>,
    pub containment_relationships: Vec<ContainmentRelation>,
    pub entity_positions: HashMap<Uuid, String>,
}

impl SpatialContext {
    /// Create a new spatial context
    pub fn new() -> Self {
        Self {
            locations: Vec::new(),
            containment_relationships: Vec::new(),
            entity_positions: HashMap::new(),
        }
    }

    /// Add a location summary
    pub fn add_location(&mut self, location: LocationSummary) {
        self.locations.push(location);
    }

    /// Add a containment relationship
    pub fn add_containment(&mut self, containment: ContainmentRelation) {
        self.containment_relationships.push(containment);
    }

    /// Set entity position
    pub fn set_entity_position(&mut self, entity_id: Uuid, position: String) {
        self.entity_positions.insert(entity_id, position);
    }
}

/// Summary of a location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationSummary {
    pub location_id: Uuid,
    pub name: String,
    pub location_type: String,
    pub description: String,
    pub entities_present: Vec<String>,
}

impl LocationSummary {
    /// Create a new location summary
    pub fn new(
        location_id: Uuid,
        name: String,
        location_type: String,
        description: String,
    ) -> Self {
        Self {
            location_id,
            name,
            location_type,
            description,
            entities_present: Vec::new(),
        }
    }

    /// Add an entity to the location
    pub fn add_entity(&mut self, entity_name: String) {
        if !self.entities_present.contains(&entity_name) {
            self.entities_present.push(entity_name);
        }
    }
}

/// Containment relationship between locations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentRelation {
    pub parent: String,
    pub child: String,
    pub relationship_type: String,
}

impl ContainmentRelation {
    /// Create a new containment relation
    pub fn new(parent: String, child: String, relationship_type: String) -> Self {
        Self {
            parent,
            child,
            relationship_type,
        }
    }
}

/// Recent change in the world model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentChange {
    pub change_id: Uuid,
    pub change_type: String,
    pub affected_entity: Option<Uuid>,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub impact_level: String,
}

impl RecentChange {
    /// Create a new recent change
    pub fn new(
        change_type: String,
        affected_entity: Option<Uuid>,
        description: String,
        impact_level: String,
    ) -> Self {
        Self {
            change_id: Uuid::new_v4(),
            change_type,
            affected_entity,
            description,
            timestamp: Utc::now(),
            impact_level,
        }
    }
}