// Entity-Component-System (ECS) core types and traits
// This module provides the foundational types for the ECS architecture
// that works symbiotically with the Chronicle narrative system.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{HashMap, HashSet};
use std::any::{Any, TypeId};
use std::time::Duration;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use thiserror::Error;

// Re-export types that CausalComponent needs
use crate::{PgPool, errors::AppError};

/// Errors that can occur in the ECS system
#[derive(Error, Debug)]
pub enum EcsError {
    #[error("Component type '{0}' not registered")]
    ComponentNotRegistered(String),
    
    #[error("Failed to serialize component: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("Component type mismatch: expected '{expected}', got '{actual}'")]
    ComponentTypeMismatch { expected: String, actual: String },
    
    #[error("Invalid archetype signature: {0}")]
    InvalidArchetype(String),
}

/// Core trait that all components must implement
pub trait Component: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static {
    /// Returns the type name of this component
    fn component_type() -> &'static str;
    
    /// Serialize the component to JSON
    fn to_json(&self) -> Result<JsonValue, EcsError> {
        Ok(serde_json::to_value(self)?)
    }
    
    /// Deserialize the component from JSON
    fn from_json(value: &JsonValue) -> Result<Self, EcsError> 
    where 
        Self: Sized 
    {
        Ok(serde_json::from_value(value.clone())?)
    }
}

/// Represents an entity in the ECS system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    id: Uuid,
    archetype_signature: String,
    component_types: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Entity {
    /// Create a new entity with the given ID and archetype signature
    pub fn new(id: Uuid, archetype_signature: &str) -> Self {
        let component_types: Vec<String> = archetype_signature
            .split('|')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
            
        Self {
            id,
            archetype_signature: archetype_signature.to_string(),
            component_types,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
    
    /// Get the entity's ID
    pub fn id(&self) -> Uuid {
        self.id
    }
    
    /// Get the entity's archetype signature
    pub fn archetype_signature(&self) -> &str {
        &self.archetype_signature
    }
    
    /// Check if this entity has a specific component type
    pub fn has_component_type(&self, component_type: &str) -> bool {
        self.component_types.contains(&component_type.to_string())
    }
    
    /// Get all component types for this entity
    pub fn component_types(&self) -> &[String] {
        &self.component_types
    }
    
    /// Update the entity's timestamp
    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }
}

/// Registry for managing component types
pub struct ComponentRegistry {
    /// Maps component type names to their TypeId for runtime type checking
    type_map: HashMap<String, TypeId>,
    /// Stores component constructors
    constructors: HashMap<String, Box<dyn Fn(JsonValue) -> Result<Box<dyn Any + Send + Sync>, EcsError> + Send + Sync>>,
}

impl ComponentRegistry {
    /// Create a new empty component registry
    pub fn new() -> Self {
        Self {
            type_map: HashMap::new(),
            constructors: HashMap::new(),
        }
    }
    
    /// Register a component type with the registry
    pub fn register<T>(&mut self, type_name: &str) 
    where 
        T: Component + Clone + 'static
    {
        let type_id = TypeId::of::<T>();
        self.type_map.insert(type_name.to_string(), type_id);
        
        // Store a constructor function for this component type
        let constructor = move |json: JsonValue| -> Result<Box<dyn Any + Send + Sync>, EcsError> {
            let component = T::from_json(&json)?;
            Ok(Box::new(component))
        };
        
        self.constructors.insert(type_name.to_string(), Box::new(constructor));
    }
    
    /// Check if a component type is registered
    pub fn is_registered(&self, type_name: &str) -> bool {
        self.type_map.contains_key(type_name)
    }
    
    /// Create a component instance from JSON data
    pub fn create_component<T>(&self, type_name: &str, data: JsonValue) -> Result<T, EcsError>
    where
        T: Component + 'static
    {
        let constructor = self.constructors
            .get(type_name)
            .ok_or_else(|| EcsError::ComponentNotRegistered(type_name.to_string()))?;
            
        let boxed_component = constructor(data)?;
        
        // Downcast to the specific type
        boxed_component
            .downcast::<T>()
            .map(|boxed| *boxed)
            .map_err(|_| EcsError::ComponentTypeMismatch {
                expected: std::any::type_name::<T>().to_string(),
                actual: type_name.to_string(),
            })
    }
    
    /// Get the TypeId for a registered component type
    pub fn get_type_id(&self, type_name: &str) -> Option<&TypeId> {
        self.type_map.get(type_name)
    }
}

impl Default for ComponentRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Common component definitions

/// Health component for entities that can take damage
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HealthComponent {
    pub current: i32,
    pub max: i32,
    pub regeneration_rate: f32,
}

impl Component for HealthComponent {
    fn component_type() -> &'static str {
        "Health"
    }
}

/// Position component for entities with a location in the world
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PositionComponent {
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub zone: String,
}

impl Component for PositionComponent {
    fn component_type() -> &'static str {
        "Position"
    }
}

/// Inventory component for entities that can hold items
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InventoryComponent {
    pub items: Vec<InventoryItem>,
    pub capacity: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InventoryItem {
    pub entity_id: Uuid,
    pub quantity: u32,
    pub slot: Option<usize>,
}

impl Component for InventoryComponent {
    fn component_type() -> &'static str {
        "Inventory"
    }
}

/// Relationships component for tracking entity-to-entity relationships
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelationshipsComponent {
    pub relationships: Vec<Relationship>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Relationship {
    pub target_entity_id: Uuid,
    pub relationship_type: String,
    pub trust: f32,
    pub affection: f32,
    pub metadata: HashMap<String, JsonValue>,
}

impl Component for RelationshipsComponent {
    fn component_type() -> &'static str {
        "Relationships"
    }
}

/// Name component for entities that have names and identifiers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NameComponent {
    pub name: String,
    pub display_name: String,
    pub aliases: Vec<String>,
}

impl Component for NameComponent {
    fn component_type() -> &'static str {
        "Name"
    }
}

// ============================================================================
// Enhanced Causal Tracking Components (Dynamic Generation Pattern)
// ============================================================================

/// Enhanced relationship categories for graph-like capabilities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RelationshipCategory {
    Social,      // Character relationships
    Spatial,     // Location-based relationships
    Causal,      // Cause-effect relationships
    Ownership,   // Possession relationships
    Temporal,    // Time-based relationships
}

impl RelationshipCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            RelationshipCategory::Social => "social",
            RelationshipCategory::Spatial => "spatial",
            RelationshipCategory::Causal => "causal",
            RelationshipCategory::Ownership => "ownership",
            RelationshipCategory::Temporal => "temporal",
        }
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "social" => Some(RelationshipCategory::Social),
            "spatial" => Some(RelationshipCategory::Spatial),
            "causal" => Some(RelationshipCategory::Causal),
            "ownership" => Some(RelationshipCategory::Ownership),
            "temporal" => Some(RelationshipCategory::Temporal),
            _ => None,
        }
    }
}

/// Temporal validity information for relationships
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemporalValidity {
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub confidence: f32,
}

/// Causal metadata for relationships
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CausalMetadata {
    pub caused_by_event: Uuid,
    pub confidence: f32,
    pub causality_type: String, // "direct", "indirect", "probabilistic"
}

/// Enhanced relationship with graph-like properties
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnhancedRelationship {
    pub target_entity_id: Uuid,
    pub relationship_type: String,
    pub category: RelationshipCategory,
    pub strength: f32, // 0.0-1.0
    pub trust: f32,
    pub affection: f32,
    pub temporal_validity: TemporalValidity,
    pub causal_metadata: Option<CausalMetadata>,
    pub metadata: HashMap<String, JsonValue>,
}

/// Helper structures for dynamic causal component generation
#[derive(Debug, Clone)]
pub struct EventChains {
    pub caused_by: Vec<Uuid>,
    pub causes: Vec<Uuid>,
    pub max_depth: u32,
}

/// Tracks causal relationships for entities (Generated dynamically, not persisted)
/// 
/// ⚠️ CRITICAL: This component is assembled at query time from:
/// - ecs_entity_relationships with category='causal'  
/// - chronicle_events.caused_by_event_id chains
/// 
/// This pattern ensures single source of truth and prevents data inconsistency.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CausalComponent {
    /// Events that caused this entity's current state
    pub caused_by_events: Vec<Uuid>,
    /// Events that this entity has caused
    pub causes_events: Vec<Uuid>,
    /// Confidence in the causal relationships (0.0-1.0)
    pub causal_confidence: f32,
    /// Maximum depth of causal chain from root cause
    pub causal_chain_depth: u32,
    /// Metadata about causal influences
    pub causal_metadata: HashMap<String, JsonValue>,
}

impl CausalComponent {
    /// Generate causal component from relationships and events
    /// 
    /// This is the core method that dynamically assembles causal information
    /// from the underlying database sources, maintaining data consistency.
    pub async fn generate_for_entity(
        entity_id: Uuid,
        user_id: Uuid,
        db_pool: &PgPool,
    ) -> Result<Self, AppError> {
        // Query causal relationships
        let causal_relationships = Self::get_causal_relationships(entity_id, user_id, db_pool).await?;
        
        // Query causal event chains
        let event_chains = Self::get_event_chains(entity_id, user_id, db_pool).await?;
        
        // Build metadata before moving event_chains
        let metadata = Self::build_metadata(&causal_relationships, &event_chains);
        
        // Assemble component
        Ok(Self {
            caused_by_events: event_chains.caused_by.clone(),
            causes_events: event_chains.causes.clone(),
            causal_confidence: Self::calculate_confidence(&causal_relationships, &event_chains),
            causal_chain_depth: event_chains.max_depth,
            causal_metadata: metadata,
        })
    }
    
    /// Query causal relationships from ecs_entity_relationships table
    async fn get_causal_relationships(
        entity_id: Uuid,
        user_id: Uuid,
        db_pool: &PgPool,
    ) -> Result<Vec<EnhancedRelationship>, AppError> {
        use crate::schema::ecs_entity_relationships;
        use diesel::prelude::*;
        
        let conn = db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
            
        let relationships = conn.interact(move |conn| {
            ecs_entity_relationships::table
                .filter(
                    ecs_entity_relationships::from_entity_id.eq(entity_id)
                    .or(ecs_entity_relationships::to_entity_id.eq(entity_id))
                )
                .filter(ecs_entity_relationships::user_id.eq(user_id))
                .filter(ecs_entity_relationships::relationship_category.eq("causal"))
                .select((
                    ecs_entity_relationships::to_entity_id,
                    ecs_entity_relationships::relationship_type,
                    ecs_entity_relationships::relationship_data,
                    ecs_entity_relationships::strength,
                    ecs_entity_relationships::causal_metadata,
                    ecs_entity_relationships::temporal_validity,
                ))
                .load::<(Uuid, String, JsonValue, Option<f64>, Option<JsonValue>, Option<JsonValue>)>(conn)
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
          .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        
        // Convert to EnhancedRelationship objects
        let mut enhanced_relationships = Vec::new();
        for (target_id, rel_type, rel_data, strength, causal_meta, temporal_val) in relationships {
            // Extract trust and affection from relationship_data
            let trust = rel_data.get("trust").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
            let affection = rel_data.get("affection").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
            
            // Parse temporal validity
            let temporal_validity = match temporal_val {
                Some(val) => serde_json::from_value(val).unwrap_or(TemporalValidity {
                    valid_from: Utc::now(),
                    valid_until: None,
                    confidence: 1.0,
                }),
                None => TemporalValidity {
                    valid_from: Utc::now(),
                    valid_until: None,
                    confidence: 1.0,
                },
            };
            
            // Parse causal metadata
            let causal_metadata = causal_meta.and_then(|val| {
                serde_json::from_value(val).ok()
            });
            
            enhanced_relationships.push(EnhancedRelationship {
                target_entity_id: target_id,
                relationship_type: rel_type,
                category: RelationshipCategory::Causal,
                strength: strength.unwrap_or(0.5) as f32,
                trust,
                affection,
                temporal_validity,
                causal_metadata,
                metadata: serde_json::from_value(rel_data).unwrap_or_default(),
            });
        }
        
        Ok(enhanced_relationships)
    }
    
    /// Query causal event chains from chronicle_events table
    async fn get_event_chains(
        entity_id: Uuid,
        user_id: Uuid,
        db_pool: &PgPool,
    ) -> Result<EventChains, AppError> {
        use crate::schema::chronicle_events;
        use diesel::prelude::*;
        
        let conn = db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
            
        // Find events where this entity was involved and trace causal chains
        let events_with_causality = conn.interact(move |conn| {
            chronicle_events::table
                .filter(chronicle_events::user_id.eq(user_id))
                .filter(chronicle_events::actors.is_not_null())
                .select((
                    chronicle_events::id,
                    chronicle_events::actors,
                    chronicle_events::caused_by_event_id,
                    chronicle_events::causes_event_ids,
                ))
                .load::<(Uuid, Option<JsonValue>, Option<Uuid>, Option<Vec<Option<Uuid>>>)>(conn)
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
          .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        
        let mut caused_by = Vec::new();
        let mut causes = Vec::new();
        let mut entity_events = Vec::new();
        
        // First pass: collect all events where entity is involved
        for (event_id, actors_json, caused_by_event, causes_events) in &events_with_causality {
            if let Some(actors) = actors_json {
                if Self::entity_involved_in_actors(&entity_id, &actors) {
                    entity_events.push((*event_id, *caused_by_event, causes_events.clone()));
                }
            }
        }
        
        // Second pass: build causal chains and calculate depth
        for (event_id, caused_by_event, causes_events) in entity_events {
            // Add to caused_by chain if this event was caused by another
            if let Some(causing_event) = caused_by_event {
                caused_by.push(causing_event);
            }
            
            // Add to causes chain if this event caused others
            if let Some(caused_events) = causes_events {
                for caused_event in caused_events.into_iter().flatten() {
                    causes.push(caused_event);
                }
            }
        }
        
        // Calculate max chain depth by finding longest chain involving entity
        let max_depth = if !caused_by.is_empty() || !causes.is_empty() {
            // Simple depth calculation: count unique causal relationships
            let unique_causers = caused_by.iter().collect::<std::collections::HashSet<_>>().len();
            let unique_caused = causes.iter().collect::<std::collections::HashSet<_>>().len();
            ((unique_causers + unique_caused).max(1)) as u32
        } else {
            0
        };
        
        Ok(EventChains {
            caused_by,
            causes,
            max_depth,
        })
    }
    
    /// Check if an entity was involved in an event based on actors JSON
    fn entity_involved_in_actors(entity_id: &Uuid, actors_json: &JsonValue) -> bool {
        if let Some(actors_array) = actors_json.as_array() {
            for actor in actors_array {
                if let Some(actor_entity_id) = actor.get("entity_id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok()) {
                    if actor_entity_id == *entity_id {
                        return true;
                    }
                }
            }
        }
        false
    }
    
    /// Calculate confidence based on relationship strength and metadata
    fn calculate_confidence(relationships: &[EnhancedRelationship], event_chains: &EventChains) -> f32 {
        // If we have explicit causal relationships, use them for confidence
        if !relationships.is_empty() {
            let total_confidence: f32 = relationships.iter()
                .map(|rel| {
                    let base_confidence = rel.strength;
                    let metadata_confidence = rel.causal_metadata
                        .as_ref()
                        .map(|meta| meta.confidence)
                        .unwrap_or(0.5);
                    (base_confidence + metadata_confidence) / 2.0
                })
                .sum();
                
            return total_confidence / relationships.len() as f32;
        }
        
        // If no explicit relationships but we have causal events, calculate base confidence
        if !event_chains.caused_by.is_empty() || !event_chains.causes.is_empty() {
            // Base confidence from event chain existence
            let event_count = event_chains.caused_by.len() + event_chains.causes.len();
            let base_confidence = 0.5; // Base confidence for implicit causality
            
            // Boost confidence based on chain depth
            let depth_factor = (event_chains.max_depth as f32).min(5.0) / 5.0;
            
            // Calculate final confidence
            (base_confidence + (depth_factor * 0.3)).min(1.0)
        } else {
            0.0
        }
    }
    
    /// Build metadata from relationships and event chains
    fn build_metadata(
        relationships: &[EnhancedRelationship],
        event_chains: &EventChains,
    ) -> HashMap<String, JsonValue> {
        let mut metadata = HashMap::new();
        
        metadata.insert("relationship_count".to_string(), 
                        JsonValue::Number(relationships.len().into()));
        metadata.insert("caused_by_count".to_string(), 
                        JsonValue::Number(event_chains.caused_by.len().into()));
        metadata.insert("causes_count".to_string(), 
                        JsonValue::Number(event_chains.causes.len().into()));
        metadata.insert("max_chain_depth".to_string(), 
                        JsonValue::Number(event_chains.max_depth.into()));
        
        // Add causality types distribution
        let causality_types: Vec<String> = relationships.iter()
            .filter_map(|rel| rel.causal_metadata.as_ref())
            .map(|meta| meta.causality_type.clone())
            .collect();
        metadata.insert("causality_types".to_string(), 
                        JsonValue::Array(causality_types.into_iter().map(JsonValue::String).collect()));
        
        metadata
    }
    
    /// Component type identifier (for compatibility with Component trait)
    pub fn component_type() -> &'static str {
        "Causal"
    }
}

// Note: CausalComponent does NOT implement the Component trait because it's dynamically generated
// and should never be persisted directly to the database.

// ============================================================================
// Temporal System Components
// ============================================================================

/// Represents game time with variable granularity and progression modes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GameTime {
    /// Absolute timestamp in game world
    pub timestamp: DateTime<Utc>,
    /// Current turn number (if turn-based)
    pub turn: Option<u64>,
    /// Current phase within turn (if applicable)
    pub phase: Option<String>,
    /// Time progression mode
    pub mode: TimeMode,
}

impl GameTime {
    /// Create a new GameTime with current timestamp
    pub fn now() -> Self {
        Self {
            timestamp: Utc::now(),
            turn: None,
            phase: None,
            mode: TimeMode::EventDriven,
        }
    }
    
    /// Create a GameTime from a turn number
    pub fn from_turn(turn: u64) -> Self {
        Self {
            timestamp: Utc::now(),
            turn: Some(turn),
            phase: None,
            mode: TimeMode::TurnBased { turn_duration: None },
        }
    }
    
    /// Get current GameTime (alias for now)
    pub fn current() -> Self {
        Self::now()
    }
}

/// Time progression modes for flexible temporal systems
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TimeMode {
    /// Real-time progression
    Continuous { tick_rate_ms: u64 },
    /// Turn-based progression
    TurnBased { turn_duration: Option<Duration> },
    /// Event-driven progression (time advances only on events)
    EventDriven,
    /// Hybrid (turns with real-time within turns)
    Hybrid { turn_duration: Duration, tick_rate_ms: u64 },
}

/// Tracks an entity's temporal existence and state changes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemporalComponent {
    /// When this entity came into existence (game time)
    pub created_at: GameTime,
    /// When this entity ceased to exist (if applicable)
    pub destroyed_at: Option<GameTime>,
    /// Last time this entity's state changed
    pub last_modified: GameTime,
    /// Whether this entity experiences time normally
    pub time_scale: f64, // 1.0 = normal, 0.0 = frozen, 2.0 = double speed
}

impl Component for TemporalComponent {
    fn component_type() -> &'static str {
        "Temporal"
    }
}

impl Default for TemporalComponent {
    fn default() -> Self {
        let now = GameTime::now();
        Self {
            created_at: now.clone(),
            destroyed_at: None,
            last_modified: now,
            time_scale: 1.0,
        }
    }
}

// ============================================================================
// Spatial Hierarchy Components
// ============================================================================

/// Size classification for spatial entities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SpatialSize {
    Tiny,    // Ring, coin
    Small,   // Dagger, potion
    Medium,  // Sword, book
    Large,   // Person, chest
    Huge,    // Table, door
    Massive, // Building, ship
}

/// Spatial capacity constraints for containers
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpatialCapacity {
    pub max_count: Option<usize>,
    pub max_volume: Option<f64>,
    pub max_mass: Option<f64>,
}

/// Spatial constraints and rules for entities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpatialConstraints {
    /// Can this entity exist in multiple locations simultaneously?
    pub allow_multiple_locations: bool,
    /// Can this entity move between containers?
    pub movable: bool,
    /// Special rules (e.g., "must_be_in_atmosphere", "requires_power")
    pub rules: Vec<String>,
}

impl Default for SpatialConstraints {
    fn default() -> Self {
        Self {
            allow_multiple_locations: false,
            movable: true,
            rules: Vec::new(),
        }
    }
}

/// Types of spatial relationships entities can have
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SpatialType {
    /// Can contain other entities
    Container {
        capacity: Option<SpatialCapacity>,
        allowed_types: Vec<String>, // Component types that can be contained
    },
    /// Can be contained by other entities
    Containable {
        size: SpatialSize,
        requires: Vec<String>, // Required container component types
    },
    /// Both container and containable
    Nested {
        container_props: Box<SpatialType>,
        containable_props: Box<SpatialType>,
    },
    /// Fixed in space, cannot be contained
    Anchored {
        coordinate_system: String,
    },
}

/// Defines spatial relationships between entities
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpatialComponent {
    /// How this entity relates to space
    pub spatial_type: SpatialType,
    /// Spatial constraints/rules
    pub constraints: SpatialConstraints,
    /// Metadata for spatial queries
    pub metadata: HashMap<String, JsonValue>,
}

impl Component for SpatialComponent {
    fn component_type() -> &'static str {
        "Spatial"
    }
}

// ============================================================================
// Entity Archetype System
// ============================================================================

/// Validation rule for entity archetypes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArchetypeValidator {
    pub rule: String,
    pub error_message: String,
}

/// Defines common patterns of components for entity creation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntityArchetype {
    /// Unique identifier for this archetype
    pub name: String,
    /// Required components
    pub required_components: Vec<String>,
    /// Optional components  
    pub optional_components: Vec<String>,
    /// Behavioral tags
    pub tags: HashSet<String>,
    /// Validation rules
    pub validators: Vec<ArchetypeValidator>,
}

/// Common archetype patterns (conventions, not enforced)
pub mod archetypes {
    /// Location entities (worlds, rooms, areas)
    pub const LOCATION: &[&str] = &["Spatial", "Temporal", "Position"];
    
    /// Actor entities (characters, NPCs)  
    pub const ACTOR: &[&str] = &["Spatial", "Temporal", "Health", "Relationships"];
    
    /// Item entities (objects, equipment)
    pub const ITEM: &[&str] = &["Spatial", "Temporal"];
    
    /// Abstract entities (concepts, organizations)
    pub const ABSTRACT: &[&str] = &["Temporal", "Relationships"];
}

// ============================================================================
// Hierarchical Query Types
// ============================================================================

/// Spatial distance measurement types for hierarchical queries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SpatialDistance {
    /// Direct containment levels (parent->child = 1)
    Hierarchical(u32),
    /// Euclidean distance (if coordinates available)
    Euclidean(f64),
    /// Graph distance through relationships
    Graph(u32),
}

/// Query types for traversing spatial hierarchies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HierarchicalQuery {
    /// Find all entities contained within target (recursively)
    ContainedWithin { entity_id: Uuid, max_depth: Option<u32> },
    
    /// Find the path from entity A to entity B through containers
    PathBetween { from: Uuid, to: Uuid },
    
    /// Find all entities of type X within spatial distance Y
    NearbyOfType { 
        origin: Uuid, 
        component_type: String,
        max_distance: SpatialDistance,
    },
    
    /// Find the "root" container (world, universe, etc.)
    RootContainer { entity_id: Uuid },
}

// ============================================================================
// Time Range Queries
// ============================================================================

/// Time range for temporal queries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimeRange {
    pub start: GameTime,
    pub end: GameTime,
}

/// Domain model for ECS component (distinct from Diesel model)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsComponent {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub component_type: String,
    pub component_data: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl EcsComponent {
    /// Create a new ECS component
    pub fn new(
        entity_id: Uuid,
        component_type: String,
        component_data: JsonValue,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            entity_id,
            component_type,
            component_data,
            created_at: now,
            updated_at: now,
        }
    }

    /// Deserialize the component data as a specific type
    pub fn as_component<T>(&self) -> Result<T, EcsError>
    where
        T: Component,
    {
        T::from_json(&self.component_data)
    }

    /// Update the component data
    pub fn update_data(&mut self, new_data: JsonValue) {
        self.component_data = new_data;
        self.updated_at = Utc::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_entity_archetype_parsing() {
        let entity = Entity::new(Uuid::new_v4(), "Character|Health|Position|Inventory");
        assert_eq!(entity.component_types().len(), 4);
        assert!(entity.has_component_type("Character"));
        assert!(entity.has_component_type("Health"));
        assert!(entity.has_component_type("Position"));
        assert!(entity.has_component_type("Inventory"));
        assert!(!entity.has_component_type("Magic"));
    }
    
    #[test]
    fn test_empty_archetype() {
        let entity = Entity::new(Uuid::new_v4(), "");
        assert_eq!(entity.component_types().len(), 0);
    }
    
    #[test]
    fn test_component_serialization() {
        let health = HealthComponent {
            current: 85,
            max: 100,
            regeneration_rate: 2.5,
        };
        
        let json = health.to_json().unwrap();
        let deserialized = HealthComponent::from_json(&json).unwrap();
        
        assert_eq!(health, deserialized);
    }
    
    #[test]
    fn test_temporal_component() {
        let temporal = TemporalComponent::default();
        
        assert_eq!(temporal.time_scale, 1.0);
        assert!(temporal.destroyed_at.is_none());
        assert_eq!(temporal.created_at.timestamp.date_naive(), temporal.last_modified.timestamp.date_naive());
    }
    
    #[test]
    fn test_spatial_component_container() {
        let spatial = SpatialComponent {
            spatial_type: SpatialType::Container {
                capacity: Some(SpatialCapacity {
                    max_count: Some(10),
                    max_volume: None,
                    max_mass: Some(100.0),
                }),
                allowed_types: vec!["Item".to_string(), "Actor".to_string()],
            },
            constraints: SpatialConstraints::default(),
            metadata: HashMap::new(),
        };
        
        let json = spatial.to_json().unwrap();
        let deserialized = SpatialComponent::from_json(&json).unwrap();
        
        assert_eq!(spatial, deserialized);
    }
    
    #[test]
    fn test_archetype_patterns() {
        assert!(archetypes::LOCATION.contains(&"Spatial"));
        assert!(archetypes::LOCATION.contains(&"Temporal"));
        assert!(archetypes::ACTOR.contains(&"Health"));
        assert!(archetypes::ITEM.contains(&"Spatial"));
        assert!(archetypes::ABSTRACT.contains(&"Relationships"));
    }
    
    #[test]
    fn test_game_time_creation() {
        let now = GameTime::now();
        let turn_time = GameTime::from_turn(42);
        
        assert!(now.turn.is_none());
        assert_eq!(turn_time.turn, Some(42));
        assert_eq!(turn_time.mode, TimeMode::TurnBased { turn_duration: None });
    }
    
    #[test]
    fn test_spatial_hierarchy_containment() {
        // Test Container -> Containable relationship
        let container = SpatialComponent {
            spatial_type: SpatialType::Container {
                capacity: Some(SpatialCapacity {
                    max_count: Some(5),
                    max_volume: Some(100.0),
                    max_mass: Some(50.0),
                }),
                allowed_types: vec!["Item".to_string()],
            },
            constraints: SpatialConstraints::default(),
            metadata: HashMap::new(),
        };
        
        let containable = SpatialComponent {
            spatial_type: SpatialType::Containable {
                size: SpatialSize::Small,
                requires: vec!["Container".to_string()],
            },
            constraints: SpatialConstraints::default(),
            metadata: HashMap::new(),
        };
        
        // Verify types
        if let SpatialType::Container { capacity, allowed_types } = &container.spatial_type {
            assert!(capacity.is_some());
            assert_eq!(allowed_types, &vec!["Item".to_string()]);
        } else {
            panic!("Expected Container type");
        }
        
        if let SpatialType::Containable { size, requires } = &containable.spatial_type {
            assert_eq!(*size, SpatialSize::Small);
            assert_eq!(requires, &vec!["Container".to_string()]);
        } else {
            panic!("Expected Containable type");
        }
    }
    
    #[test]
    fn test_spatial_nested_entity() {
        // Test universe->galaxy->world hierarchy using Nested type
        let world = SpatialComponent {
            spatial_type: SpatialType::Nested {
                container_props: Box::new(SpatialType::Container {
                    capacity: Some(SpatialCapacity {
                        max_count: None, // Unlimited actors/locations
                        max_volume: None,
                        max_mass: None,
                    }),
                    allowed_types: vec!["Actor".to_string(), "Location".to_string()],
                }),
                containable_props: Box::new(SpatialType::Containable {
                    size: SpatialSize::Massive,
                    requires: vec!["Galaxy".to_string()],
                }),
            },
            constraints: SpatialConstraints {
                allow_multiple_locations: false,
                movable: false, // Worlds don't move
                rules: vec!["requires_atmosphere".to_string()],
            },
            metadata: {
                let mut meta = HashMap::new();
                meta.insert("world_type".to_string(), JsonValue::String("terrestrial".to_string()));
                meta
            },
        };
        
        // Verify nested structure
        if let SpatialType::Nested { container_props, containable_props } = &world.spatial_type {
            if let SpatialType::Container { allowed_types, .. } = container_props.as_ref() {
                assert!(allowed_types.contains(&"Actor".to_string()));
                assert!(allowed_types.contains(&"Location".to_string()));
            }
            
            if let SpatialType::Containable { size, requires } = containable_props.as_ref() {
                assert_eq!(*size, SpatialSize::Massive);
                assert_eq!(requires, &vec!["Galaxy".to_string()]);
            }
        } else {
            panic!("Expected Nested type");
        }
        
        assert!(!world.constraints.movable);
        assert!(world.constraints.rules.contains(&"requires_atmosphere".to_string()));
    }
    
    #[test]
    fn test_hierarchical_query_types() {
        use uuid::Uuid;
        
        let entity_id = Uuid::new_v4();
        let from_id = Uuid::new_v4();
        let to_id = Uuid::new_v4();
        let origin_id = Uuid::new_v4();
        
        let contained_query = HierarchicalQuery::ContainedWithin {
            entity_id,
            max_depth: Some(3),
        };
        
        let path_query = HierarchicalQuery::PathBetween {
            from: from_id,
            to: to_id,
        };
        
        let nearby_query = HierarchicalQuery::NearbyOfType {
            origin: origin_id,
            component_type: "Actor".to_string(),
            max_distance: SpatialDistance::Hierarchical(2),
        };
        
        let root_query = HierarchicalQuery::RootContainer { entity_id };
        
        // Test serialization/deserialization
        let queries = vec![contained_query, path_query, nearby_query, root_query];
        
        for query in queries {
            let json = serde_json::to_string(&query).unwrap();
            let deserialized: HierarchicalQuery = serde_json::from_str(&json).unwrap();
            assert_eq!(query, deserialized);
        }
    }
    
    #[test]
    fn test_spatial_distance_types() {
        let hierarchical = SpatialDistance::Hierarchical(5);
        let euclidean = SpatialDistance::Euclidean(10.5);
        let graph = SpatialDistance::Graph(3);
        
        // Test serialization
        let distances = vec![hierarchical, euclidean, graph];
        for distance in distances {
            let json = serde_json::to_string(&distance).unwrap();
            let deserialized: SpatialDistance = serde_json::from_str(&json).unwrap();
            assert_eq!(distance, deserialized);
        }
    }
    
    #[test]
    fn test_spatial_component_serialization() {
        // Test all spatial types can be serialized/deserialized
        let anchored = SpatialComponent {
            spatial_type: SpatialType::Anchored {
                coordinate_system: "galactic_standard".to_string(),
            },
            constraints: SpatialConstraints::default(),
            metadata: HashMap::new(),
        };
        
        let json = serde_json::to_string(&anchored).unwrap();
        let deserialized: SpatialComponent = serde_json::from_str(&json).unwrap();
        assert_eq!(anchored, deserialized);
        
        if let SpatialType::Anchored { coordinate_system } = &deserialized.spatial_type {
            assert_eq!(coordinate_system, "galactic_standard");
        } else {
            panic!("Expected Anchored type");
        }
    }
    
    #[test]
    fn test_entity_archetype_creation() {
        use std::collections::HashSet;
        
        let mut tags = HashSet::new();
        tags.insert("interactive".to_string());
        tags.insert("persistent".to_string());
        
        let archetype = EntityArchetype {
            name: "WorldEntity".to_string(),
            required_components: vec!["Spatial".to_string(), "Temporal".to_string()],
            optional_components: vec!["Position".to_string(), "Relationships".to_string()],
            tags,
            validators: vec![
                ArchetypeValidator {
                    rule: "spatial_type_must_be_container_or_nested".to_string(),
                    error_message: "World entities must be able to contain other entities".to_string(),
                },
            ],
        };
        
        assert_eq!(archetype.name, "WorldEntity");
        assert!(archetype.required_components.contains(&"Spatial".to_string()));
        assert!(archetype.optional_components.contains(&"Position".to_string()));
        assert!(archetype.tags.contains("interactive"));
        assert_eq!(archetype.validators.len(), 1);
        
        // Test serialization
        let json = serde_json::to_string(&archetype).unwrap();
        let deserialized: EntityArchetype = serde_json::from_str(&json).unwrap();
        assert_eq!(archetype, deserialized);
    }
    
    #[test]
    fn test_temporal_component_time_scale() {
        let mut temporal = TemporalComponent::default();
        
        // Test normal time scale
        assert_eq!(temporal.time_scale, 1.0);
        
        // Test frozen time
        temporal.time_scale = 0.0;
        assert_eq!(temporal.time_scale, 0.0);
        
        // Test accelerated time
        temporal.time_scale = 2.5;
        assert_eq!(temporal.time_scale, 2.5);
        
        // Verify temporal component maintains creation time
        assert!(temporal.destroyed_at.is_none());
        assert_eq!(temporal.created_at, temporal.last_modified);
    }
}