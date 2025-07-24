# ECS System Enhancements Proposal

## Current Issues

1. **Rigid Spatial Hierarchy**: The current 3-tier system (Cosmic/Planetary/Intimate) with predefined levels doesn't support flexible containment relationships.
2. **Missing Lorebook Integration**: No tools for querying or creating lorebook entries for races, cultures, etc.
3. **Missing Chronicle Integration**: No tools for accessing historical data.
4. **No Inventory Management**: No tools for querying entity inventories.

## Proposed Solutions

### 1. Flexible Spatial Hierarchy

Replace the rigid `SpatialScale` enum with a flexible type-based system:

```rust
/// Spatial type defines what kind of spatial entity this is
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SpatialType {
    // Cosmic Scale
    Universe,
    Galaxy,
    StarSystem,
    Planet,
    Moon,
    
    // Geographic Scale
    Continent,
    Ocean,
    MountainRange,
    Desert,
    Forest,
    River,
    Lake,
    
    // Political Scale
    Empire,
    Kingdom,
    Province,
    City,
    Town,
    Village,
    District,
    
    // Structural Scale
    Fortress,
    Castle,
    Building,
    Tower,
    Floor,
    Room,
    Chamber,
    
    // Intimate Scale
    Area,
    Furniture,
    Container,
    
    // Flexible
    Custom(String), // For unique spatial types
}

/// Enhanced spatial component with flexible containment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialComponent {
    pub spatial_type: SpatialType,
    pub contained_by: Option<Uuid>, // Parent entity
    pub contains: Vec<Uuid>,         // Child entities
    pub relative_position: Option<RelativePosition>,
    pub absolute_position: Option<AbsolutePosition>,
    pub scale_metadata: HashMap<String, JsonValue>,
}
```

### 2. Lorebook Integration Tools

Create tools for the orchestrator to interact with lorebooks:

```rust
/// Query lorebook entries
pub struct QueryLorebookTool {
    lorebook_service: Arc<LorebookService>,
}

/// Parameters for lorebook queries
#[derive(Debug, Deserialize)]
pub struct QueryLorebookInput {
    pub user_id: String,
    pub query: LorebookQuery,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum LorebookQuery {
    /// Search by entry name
    ByName { name: String },
    /// Search by category (race, culture, history, etc.)
    ByCategory { category: String },
    /// Search by tags
    ByTags { tags: Vec<String> },
    /// Full-text search
    FullText { query: String },
}

/// Create or update lorebook entries
pub struct ManageLorebookTool {
    lorebook_service: Arc<LorebookService>,
}

#[derive(Debug, Deserialize)]
pub struct ManageLorebookInput {
    pub user_id: String,
    pub operation: LorebookOperation,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum LorebookOperation {
    Create {
        name: String,
        category: String,
        content: String,
        tags: Vec<String>,
    },
    Update {
        entry_id: String,
        updates: HashMap<String, JsonValue>,
    },
    Link {
        entry_id: String,
        entity_id: String,
    },
}
```

### 3. Chronicle Integration Tools

Enable access to historical narrative data:

```rust
/// Query chronicle events
pub struct QueryChronicleEventsTool {
    chronicle_service: Arc<ChronicleService>,
}

#[derive(Debug, Deserialize)]
pub struct QueryChronicleInput {
    pub user_id: String,
    pub query: ChronicleQuery,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum ChronicleQuery {
    /// Get events for a specific entity
    ByEntity { entity_id: String },
    /// Get events in a time range
    ByTimeRange { 
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
    },
    /// Get events by type
    ByEventType { event_type: String },
    /// Get events at a location
    ByLocation { location_id: String },
}
```

### 4. Inventory Management Tools

Tools for managing entity inventories:

```rust
/// Query entity inventory
pub struct QueryInventoryTool {
    entity_manager: Arc<EcsEntityManager>,
}

#[derive(Debug, Deserialize)]
pub struct QueryInventoryInput {
    pub user_id: String,
    pub entity_id: String,
    pub filter: Option<InventoryFilter>,
}

#[derive(Debug, Deserialize)]
pub struct InventoryFilter {
    pub item_type: Option<String>,
    pub tags: Option<Vec<String>>,
    pub equipped: Option<bool>,
}

/// Manage inventory operations
pub struct ManageInventoryTool {
    entity_manager: Arc<EcsEntityManager>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum InventoryOperation {
    Add {
        container_id: String,
        item_id: String,
    },
    Remove {
        container_id: String,
        item_id: String,
    },
    Transfer {
        from_id: String,
        to_id: String,
        item_id: String,
    },
    Equip {
        entity_id: String,
        item_id: String,
        slot: Option<String>,
    },
}
```

## Implementation Plan

1. **Phase 1**: Implement flexible spatial hierarchy
   - Create new `SpatialComponent` with `SpatialType`
   - Migrate existing entities to new system
   - Update world interaction tools

2. **Phase 2**: Integrate lorebook tools
   - Create `QueryLorebookTool` and `ManageLorebookTool`
   - Register with tool registry
   - Update orchestrator to use for races/cultures

3. **Phase 3**: Add chronicle integration
   - Create `QueryChronicleEventsTool`
   - Enable historical context queries

4. **Phase 4**: Implement inventory management
   - Create inventory component and tools
   - Enable container relationships

## Expected Outcomes

1. **Flexible Containment**: Dragon's Crown Peak (MountainRange) can contain Stonefang Hold (Fortress)
2. **Proper Entity Types**: "Ren" and "Shanyuan" become lorebook entries, not spatial entities
3. **Historical Context**: Orchestrator can query past events
4. **Complete Inventories**: Can query what Sol is carrying

## Migration Strategy

1. Keep existing `SpatialScale` for backward compatibility
2. Add new `SpatialType` alongside
3. Gradually migrate tools and components
4. Deprecate old system once migration complete