# ECS Temporal & Hierarchical Enhancement Design

This document outlines the design for enhancing the ECS system with temporal awareness and hierarchical entity support while maintaining maximum flexibility and abstraction.

## 1. Design Philosophy

The enhancements follow these core principles:
- **Abstraction over Prescription**: Systems should support patterns without enforcing specific domain concepts
- **Composition over Inheritance**: Entity behavior emerges from component combinations
- **Temporal Awareness**: All state changes are time-aware and can be queried historically
- **Flexible Hierarchy**: Support any containment pattern without hardcoding relationships

## 2. Temporal System Design

### 2.1 Core Temporal Components

```rust
/// Tracks an entity's temporal existence and state
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Represents game time with variable granularity
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
```

### 2.2 Turn Management

```rust
/// Manages turn progression and state transitions
pub struct TurnManager {
    /// Current game time
    current_time: GameTime,
    /// Pending state changes for current turn
    pending_changes: Vec<StateChange>,
    /// Turn processors in priority order
    processors: Vec<Box<dyn TurnProcessor>>,
}

/// Trait for implementing turn-based logic
pub trait TurnProcessor: Send + Sync {
    /// Called at the start of each turn
    fn begin_turn(&mut self, time: &GameTime) -> Result<Vec<StateChange>, AppError>;
    
    /// Process entity state for this turn
    fn process_entity(&mut self, entity: &Entity, time: &GameTime) -> Result<Vec<StateChange>, AppError>;
    
    /// Called at the end of each turn
    fn end_turn(&mut self, time: &GameTime) -> Result<Vec<StateChange>, AppError>;
    
    /// Priority for processing order
    fn priority(&self) -> i32;
}
```

### 2.3 Chronicle Integration

Chronicle events automatically trigger time progression:
- Each chronicle event has a timestamp
- Events can trigger immediate state changes or schedule future changes
- Turn advancement can be triggered by specific event patterns

## 3. Hierarchical Entity System

### 3.1 Spatial Relationship Component

Instead of hardcoded hierarchy, use a flexible spatial relationship system:

```rust
/// Defines spatial relationships between entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialComponent {
    /// How this entity relates to space
    pub spatial_type: SpatialType,
    /// Spatial constraints/rules
    pub constraints: SpatialConstraints,
    /// Metadata for spatial queries
    pub metadata: HashMap<String, JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialCapacity {
    pub max_count: Option<usize>,
    pub max_volume: Option<f64>,
    pub max_mass: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialConstraints {
    /// Can this entity exist in multiple locations simultaneously?
    pub allow_multiple_locations: bool,
    /// Can this entity move between containers?
    pub movable: bool,
    /// Special rules (e.g., "must_be_in_atmosphere", "requires_power")
    pub rules: Vec<String>,
}
```

### 3.2 Hierarchical Queries

Support queries that traverse the spatial hierarchy:

```rust
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

pub enum SpatialDistance {
    /// Direct containment levels (parent->child = 1)
    Hierarchical(u32),
    /// Euclidean distance (if coordinates available)
    Euclidean(f64),
    /// Graph distance through relationships
    Graph(u32),
}
```

## 4. Entity Archetype System

Instead of hardcoded entity types, use composable archetypes:

```rust
/// Defines common patterns of components
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchetypeValidator {
    pub rule: String,
    pub error_message: String,
}

/// Common archetype patterns (not enforced, just conventions)
pub mod archetypes {
    /// Location entities (worlds, rooms, areas)
    pub const LOCATION: &[&str] = &["Spatial.Container", "Temporal", "Position"];
    
    /// Actor entities (characters, NPCs)  
    pub const ACTOR: &[&str] = &["Spatial.Containable", "Temporal", "Health", "Relationships"];
    
    /// Item entities (objects, equipment)
    pub const ITEM: &[&str] = &["Spatial.Containable", "Temporal"];
    
    /// Abstract entities (concepts, organizations)
    pub const ABSTRACT: &[&str] = &["Temporal", "Relationships"];
}
```

## 5. Integration Examples

### 5.1 Creating a Hierarchical World

```rust
// Create a "world" entity (using LOCATION archetype)
let world = Entity::new()
    .with_component(SpatialComponent {
        spatial_type: SpatialType::Container {
            capacity: None, // Unlimited
            allowed_types: vec!["Spatial.Containable".into()],
        },
        constraints: SpatialConstraints {
            allow_multiple_locations: false,
            movable: false,
            rules: vec!["root_container".into()],
        },
        metadata: hashmap!{
            "name" => json!("Tatooine"),
            "type" => json!("planet"),
        },
    })
    .with_component(TemporalComponent {
        created_at: GameTime::now(),
        destroyed_at: None,
        last_modified: GameTime::now(),
        time_scale: 1.0,
    });

// Create a location within the world
let cantina = Entity::new()
    .with_component(SpatialComponent {
        spatial_type: SpatialType::Nested {
            container_props: Box::new(SpatialType::Container {
                capacity: Some(SpatialCapacity {
                    max_count: Some(50), // Max 50 entities
                    max_volume: None,
                    max_mass: None,
                }),
                allowed_types: vec!["Spatial.Containable".into()],
            }),
            containable_props: Box::new(SpatialType::Containable {
                size: SpatialSize::Large,
                requires: vec!["Spatial.Container".into()],
            }),
        },
        constraints: Default::default(),
        metadata: hashmap!{
            "name" => json!("Mos Eisley Cantina"),
        },
    });

// Establish containment relationship
let containment = EntityRelationship {
    from_entity_id: world.id,
    to_entity_id: cantina.id,
    relationship_type: "contains".into(),
    relationship_data: json!({
        "position": { "x": 15.5, "y": -42.3 },
        "entered_at": GameTime::now(),
    }),
};
```

### 5.2 Turn-Based State Updates

```rust
// Chronicle event triggers turn advancement
let event = ChronicleEvent {
    event_type: "combat_action",
    actors: vec!["Luke", "Stormtrooper"],
    location: Some("cantina"),
    // ...
};

// Turn processor handles combat
struct CombatProcessor;
impl TurnProcessor for CombatProcessor {
    fn process_entity(&mut self, entity: &Entity, time: &GameTime) -> Result<Vec<StateChange>> {
        if entity.has_component("Health") && entity.has_tag("in_combat") {
            // Process combat for this turn
            let changes = calculate_combat_resolution(entity, time)?;
            Ok(changes)
        } else {
            Ok(vec![])
        }
    }
}
```

### 5.3 Temporal Queries

```rust
// "What happened to Luke and where is he now?"
let query = HybridQuery {
    query_type: HybridQueryType::EntityTimeline {
        entity_name: "Luke Skywalker".into(),
        include_current_state: true,
    },
    // Include temporal context
    time_range: Some(TimeRange {
        start: GameTime::from_turn(150),
        end: GameTime::current(),
    }),
};

// "Who was in the cantina during the fight?"
let spatial_query = HierarchicalQuery::ContainedWithin {
    entity_id: cantina_id,
    max_depth: Some(1), // Direct containment only
};
```

## 6. Implementation Phases

### Phase 1: Temporal Foundation
1. Implement GameTime and TemporalComponent
2. Create TurnManager with basic turn advancement
3. Integrate with chronicle event timestamps

### Phase 2: Spatial Relationships  
1. Implement SpatialComponent with containment logic
2. Create hierarchical query system
3. Add spatial relationship validators

### Phase 3: Archetype System
1. Define EntityArchetype structure
2. Create archetype registry and validators
3. Implement archetype-based entity creation

### Phase 4: Integration
1. Update re-chronicling to create temporal/spatial components
2. Enhance hybrid queries with temporal/spatial awareness  
3. Add turn-based event processing

## 7. Benefits of This Design

1. **Maximum Flexibility**: No hardcoded concepts like "universe" or "galaxy"
2. **Temporal Intelligence**: All queries can be time-aware
3. **Natural Hierarchies**: Spatial relationships emerge from component composition
4. **Turn Agnostic**: Supports real-time, turn-based, or hybrid time models
5. **Chronicle Compatible**: Builds on existing event-driven architecture
6. **Query Power**: Complex spatial-temporal queries become possible

## 8. Future Considerations

- **Temporal Indexes**: Optimize queries across time ranges
- **Spatial Indexes**: R-trees or similar for efficient spatial queries
- **Parallel Universes**: Multiple root containers for alternate timelines
- **Time Travel**: Reverting entity states to previous turns
- **Distributed Simulation**: Partitioning spatial regions across services