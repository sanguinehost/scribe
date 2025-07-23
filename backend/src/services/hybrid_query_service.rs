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
use genai::chat::{ChatMessage, ChatRequest, ChatOptions, ChatResponseFormat, JsonSchemaSpec, ChatResponse, MessageContent, ChatRole};

use crate::{
    PgPool,
    config::NarrativeFeatureFlags,
    errors::AppError,
    llm::AiClient,
    models::chronicle_event::ChronicleEvent,
    services::{
        agentic::relationship_analysis_structured_output::{
            RelationshipAnalysisOutput, get_relationship_analysis_schema
        },
        agentic::narrative_answer_generation_structured_output::{
            NarrativeGenerationOutput, get_narrative_generation_schema
        },
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
    /// "Track ownership history of an item"
    ItemTimeline,
    /// "Show item usage patterns"
    ItemUsage,
    /// "Where has this item been?"
    ItemLocation,
    /// "Track item lifecycle from creation to destruction"
    ItemLifecycle,
    /// "Who has interacted with this item?"
    ItemInteractions,
    /// "Find items matching criteria"
    ItemSearch,
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
    /// Item timelines and ownership history
    pub item_timelines: Vec<ItemTimeline>,
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
    /// Rich context extracted from event content
    pub extracted_context: ExtractedEntityContext,
    /// Items owned or interacted with
    pub item_interactions: Vec<ItemInteraction>,
}

/// Rich context extracted from event content
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtractedEntityContext {
    /// Attributes extracted from event content
    pub attributes: HashMap<String, JsonValue>,
    /// Dialogue reveals (what we learn from dialogue)
    pub dialogue_reveals: HashMap<String, String>,
    /// Skills and abilities mentioned
    pub skills: Vec<String>,
    /// Equipment and items mentioned
    pub equipment: Vec<String>,
    /// Profession or role
    pub profession: Option<String>,
    /// Background information
    pub background: Vec<String>,
    /// Notable actions performed
    pub actions: Vec<String>,
}

/// Item interaction record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemInteraction {
    /// Item identification
    pub item_id: Uuid,
    /// Item name
    pub item_name: String,
    /// Type of interaction
    pub interaction_type: ItemInteractionType,
    /// When the interaction occurred
    pub event_id: Uuid,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Additional interaction details
    pub details: Option<JsonValue>,
}

/// Types of item interactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ItemInteractionType {
    /// Item was discovered/found
    Discovered,
    /// Item was created/crafted
    Created,
    /// Item ownership was transferred
    Transferred { from: Option<Uuid>, to: Option<Uuid> },
    /// Item was used
    Used { usage_type: String, remaining: Option<String> },
    /// Item was placed at location
    Placed { location: Option<String> },
    /// Item was moved
    Moved { from_location: Option<String>, to_location: Option<String> },
    /// Item was destroyed
    Destroyed { cause: Option<String> },
    /// Generic interaction
    Interacted { action: String },
}

/// Item ownership and usage timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemTimeline {
    /// Item identification
    pub item_id: Uuid,
    /// Item name
    pub item_name: String,
    /// Ownership history
    pub ownership_history: Vec<ItemOwnershipRecord>,
    /// Usage patterns
    pub usage_patterns: Vec<ItemUsagePattern>,
    /// Current owner (if any)
    pub current_owner: Option<Uuid>,
    /// Current location (if known)
    pub current_location: Option<String>,
    /// Item status
    pub status: ItemStatus,
}

/// Item ownership record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemOwnershipRecord {
    /// Owner entity ID
    pub owner_id: Uuid,
    /// When ownership started
    pub from_event_id: Uuid,
    pub from_timestamp: DateTime<Utc>,
    /// When ownership ended (if applicable)
    pub to_event_id: Option<Uuid>,
    pub to_timestamp: Option<DateTime<Utc>>,
    /// How ownership was acquired
    pub acquisition_method: String,
}

/// Item usage pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemUsagePattern {
    /// User entity ID
    pub user_id: Uuid,
    /// Usage event
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    /// Type of usage
    pub usage_type: String,
    /// Context of usage
    pub context: Option<String>,
    /// Effect or result
    pub effect: Option<String>,
}

/// Item status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ItemStatus {
    /// Item exists and is functional
    Active,
    /// Item was used up/depleted
    Depleted,
    /// Item was destroyed
    Destroyed,
    /// Item is missing/lost
    Lost,
    /// Status unknown
    Unknown,
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

/// Structured output schema for entity context extraction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityContextOutput {
    pub attributes: HashMap<String, serde_json::Value>,
    pub dialogue_reveals: HashMap<String, String>,
    pub skills: Vec<String>,
    pub equipment: Vec<String>,
    pub profession: Option<String>,
    pub background: Vec<String>,
    pub actions: Vec<String>,
}

/// Structured output schema for item analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemAnalysisOutput {
    pub items: Vec<SingleItemAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleItemAnalysis {
    pub item_id: String,
    pub item_name: String,
    pub ownership_timeline: Vec<OwnershipEventOutput>,
    pub usage_patterns: Vec<UsagePatternOutput>,
    pub lifecycle_stage: String,
    pub location_history: Vec<LocationEventOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipEventOutput {
    pub timestamp: String,
    pub previous_owner: Option<String>,
    pub new_owner: String,
    pub transfer_type: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsagePatternOutput {
    pub usage_type: String,
    pub frequency: String,
    pub context: String,
    pub effectiveness: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationEventOutput {
    pub timestamp: String,
    pub location: String,
    pub event_type: String,
    pub context: Option<String>,
}

/// Helper functions to create JSON schemas for structured output
pub fn get_entity_context_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "attributes": {
                "type": "object",
                "description": "Key-value pairs of entity attributes extracted from events"
            },
            "dialogue_reveals": {
                "type": "object",
                "description": "Information revealed through dialogue, keyed by topic"
            },
            "skills": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Skills mentioned or demonstrated by the entity"
            },
            "equipment": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Equipment or items associated with the entity"
            },
            "profession": {
                "type": "string",
                "description": "The entity's profession or occupation"
            },
            "background": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Background information about the entity"
            },
            "actions": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Actions taken by the entity"
            }
        },
        "required": ["attributes", "dialogue_reveals", "skills", "equipment", "background", "actions"],
        "additionalProperties": false
    })
}

pub fn get_item_analysis_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "item_id": {
                            "type": "string",
                            "description": "Unique identifier for the item"
                        },
                        "item_name": {
                            "type": "string",
                            "description": "Name of the item"
                        },
                        "ownership_timeline": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "timestamp": {"type": "string"},
                                    "previous_owner": {"type": "string"},
                                    "new_owner": {"type": "string"},
                                    "transfer_type": {"type": "string"},
                                    "context": {"type": "string"}
                                },
                                "required": ["timestamp", "new_owner", "transfer_type"]
                            },
                            "description": "Timeline of ownership changes"
                        },
                        "usage_patterns": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "usage_type": {"type": "string"},
                                    "frequency": {"type": "string"},
                                    "context": {"type": "string"},
                                    "effectiveness": {"type": "string"}
                                },
                                "required": ["usage_type", "frequency", "context"]
                            },
                            "description": "Patterns of how the item is used"
                        },
                        "lifecycle_stage": {
                            "type": "string",
                            "description": "Current stage in the item's lifecycle"
                        },
                        "location_history": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "timestamp": {"type": "string"},
                                    "location": {"type": "string"},
                                    "event_type": {"type": "string"},
                                    "context": {"type": "string"}
                                },
                                "required": ["timestamp", "location", "event_type"]
                            },
                            "description": "History of where the item has been"
                        }
                    },
                    "required": ["item_id", "item_name", "ownership_timeline", "usage_patterns", "lifecycle_stage", "location_history"]
                },
                "description": "List of items found in the events"
            }
        },
        "required": ["items"],
        "additionalProperties": false
    })
}

/// Validation and conversion methods for structured outputs
impl EntityContextOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        // Basic validation - ensure required fields are present
        if self.attributes.is_empty() && self.dialogue_reveals.is_empty() && 
           self.skills.is_empty() && self.equipment.is_empty() && 
           self.background.is_empty() && self.actions.is_empty() {
            return Err(AppError::InvalidInput(
                "Entity context output must contain at least some data".to_string()
            ));
        }
        Ok(())
    }
}

impl ItemAnalysisOutput {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.items.is_empty() {
            return Err(AppError::InvalidInput(
                "Item analysis must contain at least one item".to_string()
            ));
        }
        
        for item in &self.items {
            if item.item_id.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Item ID cannot be empty".to_string()
                ));
            }
            
            if item.item_name.trim().is_empty() {
                return Err(AppError::InvalidInput(
                    "Item name cannot be empty".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    pub fn to_item_timelines(&self) -> Result<Vec<ItemTimeline>, AppError> {
        use uuid::Uuid;
        use chrono::Utc;
        
        let mut timelines = Vec::new();
        
        for item in &self.items {
            // Parse item ID
            let item_id = Uuid::parse_str(&item.item_id)
                .map_err(|_| AppError::InvalidInput("Invalid item ID format".to_string()))?;
            
            // Convert ownership timeline to ItemOwnershipRecord format
            let mut ownership_history = Vec::new();
            for event in &item.ownership_timeline {
                // For simplified conversion, we'll create basic ownership records
                // In practice, this would need proper timestamp parsing and UUID handling
                let owner_id = Uuid::new_v4(); // Placeholder - would need proper entity resolution
                let timestamp = Utc::now(); // Placeholder - would need proper timestamp parsing
                let event_id = Uuid::new_v4(); // Placeholder - would need proper event ID
                
                ownership_history.push(ItemOwnershipRecord {
                    owner_id,
                    from_event_id: event_id,
                    from_timestamp: timestamp,
                    to_event_id: None,
                    to_timestamp: None,
                    acquisition_method: event.transfer_type.clone(),
                });
            }
            
            // Convert usage patterns to ItemUsagePattern format
            let mut usage_patterns = Vec::new();
            for pattern in &item.usage_patterns {
                let user_id = Uuid::new_v4(); // Placeholder - would need proper entity resolution
                let timestamp = Utc::now(); // Placeholder - would need proper timestamp parsing
                let event_id = Uuid::new_v4(); // Placeholder - would need proper event ID
                
                usage_patterns.push(ItemUsagePattern {
                    user_id,
                    event_id,
                    timestamp,
                    usage_type: pattern.usage_type.clone(),
                    context: Some(pattern.context.clone()),
                    effect: pattern.effectiveness.clone(),
                });
            }
            
            // Determine item status from lifecycle stage
            let status = match item.lifecycle_stage.as_str() {
                "created" => ItemStatus::Active,
                "active" => ItemStatus::Active,
                "depleted" => ItemStatus::Depleted,
                "destroyed" => ItemStatus::Destroyed,
                "lost" => ItemStatus::Lost,
                _ => ItemStatus::Unknown, // Default
            };
            
            timelines.push(ItemTimeline {
                item_id,
                item_name: item.item_name.clone(),
                ownership_history,
                usage_patterns,
                current_owner: None, // Would need to be determined from latest ownership
                current_location: item.location_history.last().map(|l| l.location.clone()),
                status,
            });
        }
        
        Ok(timelines)
    }
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
    /// AI client for analysis
    ai_client: Arc<dyn AiClient>,
    /// Model to use for AI queries
    model: String,
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
        ai_client: Arc<dyn AiClient>,
        model: String,
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
            ai_client,
            model,
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
        
        // Step 5: Build item timelines if this is an item query
        let item_timelines = if self.is_item_query(&query.query_type) {
            self.build_item_timelines(&chronicle_events, query).await?
        } else {
            Vec::new()
        };

        // Step 6: Generate summary and insights
        let summary = self.generate_query_summary(&entity_contexts, &chronicle_events, &relationships, query).await?;

        Ok(HybridQueryResult {
            query_type: query.query_type.clone(),
            user_id: query.user_id,
            entities: entity_contexts,
            chronicle_events,
            relationships,
            item_timelines,
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
        
        // Build item timelines if this is an item query
        let item_timelines = if self.is_item_query(&query.query_type) {
            self.build_item_timelines(&chronicle_events, query).await?
        } else {
            Vec::new()
        };

        // Generate narrative even for fallback queries
        let narrative_answer = self.generate_narrative_answer(
            &entity_contexts,
            &chronicle_events,
            &[], // No relationships in fallback mode
            query
        ).await?;

        let summary = HybridQuerySummary {
            entities_found: entity_contexts.len(),
            events_analyzed: chronicle_events.len(),
            relationships_found: 0,
            key_insights: vec!["Limited analysis - ECS data unavailable".to_string()],
            narrative_answer: Some(narrative_answer),
        };

        Ok(HybridQueryResult {
            query_type: query.query_type.clone(),
            user_id: query.user_id,
            entities: entity_contexts,
            chronicle_events,
            relationships: Vec::new(),
            item_timelines,
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
            // Item query types
            HybridQueryType::ItemTimeline => {
                "Item ownership timeline and history".to_string()
            }
            HybridQueryType::ItemUsage => {
                "Item usage patterns and frequency".to_string()
            }
            HybridQueryType::ItemLocation => {
                "Item location history and movements".to_string()
            }
            HybridQueryType::ItemLifecycle => {
                "Item lifecycle from creation to destruction".to_string()
            }
            HybridQueryType::ItemInteractions => {
                "Entities that have interacted with items".to_string()
            }
            HybridQueryType::ItemSearch => {
                "Search for items matching criteria".to_string()
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

        // Extract rich context from events
        let extracted_context = self.extract_entity_context_from_events(entity_id, events).await?;
        
        // Extract item interactions
        let item_interactions = self.extract_item_interactions(entity_id, events).await?;
        
        // Calculate relevance score based on query and entity context
        let relevance_score = self.calculate_entity_relevance_score(entity_id, &timeline_events, &current_state, query).await?;

        Ok(EntityTimelineContext {
            entity_id,
            entity_name: self.extract_entity_name(entity_id).await?,
            current_state,
            timeline_events,
            relationships,
            relevance_score,
            extracted_context,
            item_interactions,
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

    /// Extract co-participants from an event using AI analysis
    async fn extract_co_participants(&self, entity_id: Uuid, event: &ChronicleEvent) -> Result<Vec<Uuid>, AppError> {
        use crate::services::agentic::event_participants_structured_output::{
            get_event_participants_schema, EventParticipantsOutput
        };
        use genai::chat::{ChatRequest, ChatOptions, ChatResponseFormat, JsonSchemaSpec, MessageContent};
        
        debug!("Extracting co-participants for entity {} from event {} using AI", entity_id, event.id);
        
        // Build comprehensive event context for AI analysis
        let mut event_context = format!(
            "Event Type: {}\nEvent Action: {}\nSummary: {}\nTimestamp: {}",
            event.event_type,
            event.action.as_deref().unwrap_or("Unknown"),
            event.summary,
            event.timestamp_iso8601
        );
        
        // Add actors information if available
        if let Ok(actors) = event.get_actors() {
            event_context.push_str("\n\nActors:");
            for actor in &actors {
                event_context.push_str(&format!(
                    "\n- Entity ID: {}, Role: {:?}, Context: {:?}",
                    actor.entity_id,
                    actor.role,
                    actor.context
                ));
            }
        }
        
        // Add event data if available
        if let Some(event_data) = &event.event_data {
            event_context.push_str(&format!("\n\nEvent Data: {}", 
                serde_json::to_string_pretty(event_data).unwrap_or_else(|_| event_data.to_string())
            ));
        }
        
        let prompt = format!(
            r#"Analyze the following chronicle event and extract ALL participants with their roles and relationships.

Event Context:
{}

Instructions:
1. Identify PRIMARY participants - those directly performing actions or being acted upon
2. Identify SECONDARY participants - those in supporting roles, facilitating, or observing
3. Identify MENTIONED participants - entities referenced but not directly involved
4. Analyze relationships between participants in the context of this event
5. Consider both explicit mentions and implicit involvement

Look for participants in:
- The actors list
- The event summary
- Event data fields (actors, participants, targets, subjects)
- Narrative descriptions that imply involvement
- Contextual references to entities

For each participant, determine:
- Their role (agent, patient, observer, etc.)
- Their involvement type (active, passive, mentioned, etc.)
- What actions they performed
- Their relationships to other participants

Return a comprehensive participant analysis with confidence scores."#,
            event_context
        );
        
        // Get the JSON schema for structured output
        let schema = get_event_participants_schema();
        
        // Create chat request with structured output
        let chat_options = ChatOptions::default()
            .with_temperature(0.3)
            .with_response_format(ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec {
                schema: schema.clone(),
            }));
        
        let messages = vec![
            ChatMessage::system("You are an expert narrative analyst specializing in identifying event participants and their roles."),
            ChatMessage::user(MessageContent::Text(prompt)),
        ];
        
        let chat_request = ChatRequest::new(messages);
        
        let response = self.ai_client.exec_chat(&self.model, chat_request, Some(chat_options)).await
            .map_err(|e| AppError::AiServiceError(format!("Failed to analyze event participants: {}", e)))?;
        
        // Parse the structured response
        let content = response.contents
            .first()
            .and_then(|c| match c {
                MessageContent::Text(text) => Some(text.clone()),
                _ => None,
            })
            .ok_or_else(|| AppError::AiServiceError("No content in participant analysis response".to_string()))?;
        
        let participants_output: EventParticipantsOutput = serde_json::from_str(&content)
            .map_err(|e| AppError::AiServiceError(format!("Failed to parse participant analysis: {}", e)))?;
        
        // Validate the output
        participants_output.validate()?;
        
        // Convert to UUID list, excluding the requesting entity
        let co_participants = participants_output.to_participant_ids(Some(entity_id));
        
        debug!("AI extracted {} co-participants (confidence: {:.2}): {} primary, {} secondary, {} mentioned", 
               co_participants.len(),
               participants_output.confidence_score,
               participants_output.primary_participants.len(),
               participants_output.secondary_participants.len(),
               participants_output.mentioned_participants.len()
        );
        
        // Log participant relationships for debugging
        for rel in &participants_output.participant_relationships {
            debug!("  Relationship: {} {} {} (strength: {:.2})",
                   rel.from_participant,
                   rel.relationship_type,
                   rel.to_participant,
                   rel.strength
            );
        }
        
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
    
    /// Extract rich context about an entity from event content using Flash-Lite
    async fn extract_entity_context_from_events(
        &self,
        entity_id: Uuid,
        events: &[ChronicleEvent],
    ) -> Result<ExtractedEntityContext, AppError> {
        debug!("Extracting entity context for {} from {} events using Flash-Lite", entity_id, events.len());
        
        // Prepare event data for AI analysis
        let mut relevant_events = Vec::new();
        for event in events {
            if self.is_entity_in_event(entity_id, event).await? {
                relevant_events.push(event);
            }
        }
        
        if relevant_events.is_empty() {
            return Ok(ExtractedEntityContext::default());
        }
        
        // Use Flash-Lite for context extraction from event content
        self.extract_context_with_flash_lite(entity_id, &relevant_events).await
    }
    
    /// Check if entity is mentioned in an event
    async fn is_entity_in_event(&self, entity_id: Uuid, event: &ChronicleEvent) -> Result<bool, AppError> {
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

    /// Extract entity context using Flash-Lite AI analysis
    async fn extract_context_with_flash_lite(
        &self,
        entity_id: Uuid,
        events: &[&ChronicleEvent],
    ) -> Result<ExtractedEntityContext, AppError> {
        debug!("Using Flash-Lite to extract context for entity {} from {} events", entity_id, events.len());
        
        // Prepare events data for AI analysis
        let events_data = self.prepare_events_for_context_analysis(entity_id, events).await?;
        
        // Create AI prompt for entity context extraction
        let prompt = format!(
            r#"Analyze the following chronicle events to extract rich context about the entity with ID {}.

EVENTS TO ANALYZE:
{}

Extract the following information and respond in JSON format:
{{
  "attributes": {{"key": "value"}}, // Physical, mental, or behavioral attributes
  "dialogue_reveals": {{"aspect": "what_was_revealed"}}, // Information revealed through dialogue
  "skills": ["skill1", "skill2"], // Demonstrated skills or abilities
  "equipment": ["item1", "item2"], // Equipment, tools, or items associated with the entity
  "profession": "profession_name", // Profession or role if identifiable
  "background": ["element1", "element2"], // Background, history, or education elements
  "actions": ["action1", "action2"] // Significant actions performed
}}

Focus on extracting information that is explicitly mentioned or strongly implied in the events. Return only the JSON object."#,
            entity_id,
            events_data
        );
        
        // Configure structured output for entity context extraction
        // Use Gemini-compatible schema (without additionalProperties)
        let schema = crate::services::hybrid_query_gemini_schemas::get_entity_context_schema_gemini();
        let mut chat_options = ChatOptions::default();
        chat_options = chat_options.with_temperature(0.1);
        chat_options = chat_options.with_max_tokens(1000);
        chat_options = chat_options.with_response_format(ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec {
            schema: schema.clone(),
        }));
        
        let chat_request = ChatRequest::from_user(prompt);
        
        // Use Flash-Lite for fast, cost-effective analysis
        let response = self.ai_client
            .exec_chat(
                &self.model,
                chat_request,
                Some(chat_options),
            )
            .await
            .map_err(|e| AppError::LlmClientError(format!("Flash-Lite context extraction failed: {}", e)))?;
        
        // Parse the AI response
        self.parse_context_extraction_response(&response)
    }
    
    /// Prepare events data for AI context analysis
    async fn prepare_events_for_context_analysis(
        &self,
        entity_id: Uuid,
        events: &[&ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut events_text = String::new();
        
        for (i, event) in events.iter().enumerate() {
            events_text.push_str(&format!("\n--- Event {} ---\n", i + 1));
            events_text.push_str(&format!("Summary: {}\n", event.summary));
            events_text.push_str(&format!("Type: {}\n", event.event_type));
            events_text.push_str(&format!("Timestamp: {}\n", event.timestamp_iso8601));
            
            if let Some(event_data) = &event.event_data {
                // Extract content
                if let Some(content) = event_data.get("content").and_then(|c| c.as_str()) {
                    events_text.push_str(&format!("Content: {}\n", content));
                }
                
                // Extract actors info
                if let Some(actors) = event_data.get("actors").and_then(|a| a.as_array()) {
                    events_text.push_str("Actors: ");
                    for actor in actors {
                        if let Some(context) = actor.get("context").and_then(|c| c.as_str()) {
                            if let Some(actor_id) = actor.get("entity_id").and_then(|id| id.as_str()) {
                                if actor_id == &entity_id.to_string() {
                                    events_text.push_str(&format!("[FOCUS: {}] ", context));
                                } else {
                                    events_text.push_str(&format!("{} ", context));
                                }
                            }
                        }
                    }
                    events_text.push('\n');
                }
                
                // Include other relevant data as needed
                for (key, value) in event_data.as_object().unwrap_or(&serde_json::Map::new()) {
                    if key != "content" && key != "actors" {
                        events_text.push_str(&format!("{}: {}\n", key, value));
                    }
                }
            }
        }
        
        Ok(events_text)
    }
    
    /// Parse AI response for entity context extraction
    fn parse_context_extraction_response(
        &self,
        response: &ChatResponse,
    ) -> Result<ExtractedEntityContext, AppError> {
        use genai::chat::MessageContent;
        
        // Extract text from ChatResponse
        let response_text = response.contents
            .iter()
            .find_map(|content| match content {
                MessageContent::Text(text) => Some(text.clone()),
                _ => None,
            })
            .ok_or_else(|| AppError::InternalServerErrorGeneric(
                "No text content found in AI response".to_string()
            ))?;
        
        // Parse the structured response directly as JSON
        let entity_output: EntityContextOutput = serde_json::from_str(&response_text)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to parse entity context JSON: {}", e)))?;
        
        // Validate the output
        entity_output.validate()?;
        
        // Convert from structured output to ExtractedEntityContext
        let mut context = ExtractedEntityContext::default();
        context.attributes = entity_output.attributes;
        context.dialogue_reveals = entity_output.dialogue_reveals;
        context.skills = entity_output.skills;
        context.equipment = entity_output.equipment;
        context.profession = entity_output.profession;
        context.background = entity_output.background;
        context.actions = entity_output.actions;
        
        Ok(context)
    }
    
    /// Extract JSON from AI response (handles markdown, etc.)
    fn extract_json_from_ai_response(&self, response: &str) -> Result<String, AppError> {
        let cleaned = if response.trim().starts_with("```json") {
            let start = response.find("```json").unwrap() + 7;
            if let Some(end) = response[start..].find("```") {
                response[start..start + end].trim()
            } else {
                response[start..].trim()
            }
        } else if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                &response[start..=end]
            } else {
                response
            }
        } else {
            response
        };

        Ok(cleaned.to_string())
    }
    
    /// Recursively extract context from nested JSON
    fn extract_context_from_nested_json(
        &self,
        context: &mut ExtractedEntityContext,
        json_obj: &serde_json::Map<String, JsonValue>,
        entity_id: Uuid,
    ) {
        // Limit recursion depth to prevent stack overflow
        self.extract_context_from_nested_json_recursive(context, json_obj, entity_id, 0, 5);
    }
    
    fn extract_context_from_nested_json_recursive(
        &self,
        context: &mut ExtractedEntityContext,
        json_obj: &serde_json::Map<String, JsonValue>,
        entity_id: Uuid,
        depth: usize,
        max_depth: usize,
    ) {
        if depth >= max_depth {
            return;
        }
        
        for (key, value) in json_obj {
            match value {
                JsonValue::Object(nested_obj) => {
                    // Check if this object contains entity-specific data
                    if let Some(entity_field) = nested_obj.get("entity_id") {
                        if let Some(id_str) = entity_field.as_str() {
                            if let Ok(id) = Uuid::parse_str(id_str) {
                                if id == entity_id {
                                    // Extract all fields from this object
                                    for (field_key, field_value) in nested_obj {
                                        if field_key != "entity_id" {
                                            // Include the parent key for context
                                            let full_key = format!("{}.{}", key, field_key);
                                            context.attributes.insert(full_key, field_value.clone());
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    // Continue recursion
                    self.extract_context_from_nested_json_recursive(
                        context, nested_obj, entity_id, depth + 1, max_depth
                    );
                }
                JsonValue::Array(array) => {
                    // Process arrays that might contain entity data
                    for item in array {
                        if let JsonValue::Object(item_obj) = item {
                            self.extract_context_from_nested_json_recursive(
                                context, item_obj, entity_id, depth + 1, max_depth
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }
    
    /// Extract item interactions for an entity
    async fn extract_item_interactions(
        &self,
        entity_id: Uuid,
        events: &[ChronicleEvent],
    ) -> Result<Vec<ItemInteraction>, AppError> {
        let mut interactions = Vec::new();
        
        for event in events {
            if let Some(event_data) = &event.event_data {
                // Check items array
                if let Some(items_value) = event_data.get("items") {
                    if let Some(items_array) = items_value.as_array() {
                        for item_value in items_array {
                            if let Some(item_obj) = item_value.as_object() {
                                // Check if entity is involved with this item
                                let involved = self.is_entity_involved_with_item(entity_id, item_obj);
                                
                                if involved {
                                    if let Some(interaction) = self.parse_item_interaction(
                                        item_obj, entity_id, event.id, event.timestamp_iso8601
                                    ) {
                                        interactions.push(interaction);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Sort by timestamp
        interactions.sort_by_key(|i| i.timestamp);
        
        Ok(interactions)
    }
    
    /// Check if entity is involved with an item
    fn is_entity_involved_with_item(
        &self,
        entity_id: Uuid,
        item_obj: &serde_json::Map<String, JsonValue>,
    ) -> bool {
        // Check owner field
        if let Some(owner) = item_obj.get("owner").and_then(|o| o.as_str()) {
            if let Ok(owner_id) = Uuid::parse_str(owner) {
                if owner_id == entity_id {
                    return true;
                }
            }
        }
        
        // Check from_owner and to_owner for transfers
        if let Some(from) = item_obj.get("from_owner").and_then(|f| f.as_str()) {
            if let Ok(from_id) = Uuid::parse_str(from) {
                if from_id == entity_id {
                    return true;
                }
            }
        }
        
        if let Some(to) = item_obj.get("to_owner").and_then(|t| t.as_str()) {
            if let Ok(to_id) = Uuid::parse_str(to) {
                if to_id == entity_id {
                    return true;
                }
            }
        }
        
        // Check user field for usage
        if let Some(user) = item_obj.get("user").and_then(|u| u.as_str()) {
            if let Ok(user_id) = Uuid::parse_str(user) {
                if user_id == entity_id {
                    return true;
                }
            }
        }
        
        // Check creator field
        if let Some(creator) = item_obj.get("creator").and_then(|c| c.as_str()) {
            if let Ok(creator_id) = Uuid::parse_str(creator) {
                if creator_id == entity_id {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Parse item interaction from JSON
    fn parse_item_interaction(
        &self,
        item_obj: &serde_json::Map<String, JsonValue>,
        _entity_id: Uuid, // TODO: Add to ItemInteraction struct to track who performed the interaction
        event_id: Uuid,
        timestamp: DateTime<Utc>,
    ) -> Option<ItemInteraction> {
        let item_id = item_obj.get("item_id")
            .and_then(|id| id.as_str())
            .and_then(|id| Uuid::parse_str(id).ok())?;
            
        let item_name = item_obj.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("Unknown Item")
            .to_string();
            
        let action = item_obj.get("action")
            .and_then(|a| a.as_str())
            .unwrap_or("interacted");
            
        let interaction_type = match action {
            "discovered" => ItemInteractionType::Discovered,
            "created" => ItemInteractionType::Created,
            "transferred" => {
                let from = item_obj.get("from_owner")
                    .and_then(|f| f.as_str())
                    .and_then(|f| Uuid::parse_str(f).ok());
                let to = item_obj.get("to_owner")
                    .and_then(|t| t.as_str())
                    .and_then(|t| Uuid::parse_str(t).ok());
                ItemInteractionType::Transferred { from, to }
            }
            "used" => {
                let usage_type = item_obj.get("usage_type")
                    .and_then(|u| u.as_str())
                    .unwrap_or("generic")
                    .to_string();
                let remaining = item_obj.get("remaining")
                    .and_then(|r| r.as_str())
                    .map(|r| r.to_string());
                ItemInteractionType::Used { usage_type, remaining }
            }
            "placed" => {
                let location = item_obj.get("location")
                    .and_then(|l| l.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|n| n.to_string());
                ItemInteractionType::Placed { location }
            }
            "moved" => {
                let from_location = item_obj.get("from_location")
                    .and_then(|l| l.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|n| n.to_string());
                let to_location = item_obj.get("to_location")
                    .and_then(|l| l.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|n| n.to_string());
                ItemInteractionType::Moved { from_location, to_location }
            }
            "destroyed" | "depleted" => {
                let cause = item_obj.get("destruction_cause")
                    .or_else(|| item_obj.get("cause"))
                    .and_then(|c| c.as_str())
                    .map(|c| c.to_string());
                ItemInteractionType::Destroyed { cause }
            }
            _ => {
                ItemInteractionType::Interacted { action: action.to_string() }
            }
        };
        
        // Get additional details
        let details = item_obj.get("details").cloned();
        
        Some(ItemInteraction {
            item_id,
            item_name,
            interaction_type,
            event_id,
            timestamp,
            details,
        })
    }
    
    /// Check if query is an item-related query
    fn is_item_query(&self, query_type: &HybridQueryType) -> bool {
        matches!(
            query_type,
            HybridQueryType::ItemTimeline |
            HybridQueryType::ItemUsage |
            HybridQueryType::ItemLocation |
            HybridQueryType::ItemLifecycle |
            HybridQueryType::ItemInteractions |
            HybridQueryType::ItemSearch
        )
    }
    
    /// Build item timelines from chronicle events using AI analysis
    async fn build_item_timelines(
        &self,
        events: &[ChronicleEvent],
        query: &HybridQuery,
    ) -> Result<Vec<ItemTimeline>, AppError> {
        debug!("Building item timelines from {} events using AI analysis", events.len());
        
        // Use AI to analyze events for item information
        let item_analysis = self.analyze_items_with_flash_lite(events, query).await?;
        
        // Filter based on query type using AI insights
        let filtered_timelines = self.filter_item_timelines_by_query(
            item_analysis,
            query,
        ).await?;
        
        Ok(filtered_timelines)
    }

    /// Analyze events for item information using Flash-Lite with structured output
    async fn analyze_items_with_flash_lite(
        &self,
        events: &[ChronicleEvent],
        query: &HybridQuery,
    ) -> Result<Vec<ItemTimeline>, AppError> {
        debug!("Using Flash-Lite to analyze item information from events");
        
        // Prepare events data for AI analysis
        let events_data = self.prepare_events_for_item_analysis(events).await?;
        
        if events_data.trim().is_empty() {
            return Ok(Vec::new());
        }
        
        // Create structured prompt for item analysis
        let prompt = format!(
            r#"Analyze the following chronicle events to extract comprehensive item information.

EVENTS TO ANALYZE:
{}

Query Type: {:?}

Extract item timelines including:
- Item identities (IDs, names)
- Ownership changes and transfers
- Usage patterns and interactions
- Location movements
- Creation, modification, and destruction events
- Entity interactions with items

Focus on items relevant to the query. Extract only what is explicitly mentioned or strongly implied in the events."#,
            events_data,
            query.query_type
        );
        
        // Configure structured output for item analysis
        // Use Gemini-compatible schema (without additionalProperties)
        let schema = crate::services::hybrid_query_gemini_schemas::get_item_analysis_schema_gemini();
        let mut chat_options = ChatOptions::default();
        chat_options = chat_options.with_temperature(0.2);
        chat_options = chat_options.with_max_tokens(2000);
        chat_options = chat_options.with_response_format(ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec {
            schema: schema.clone(),
        }));
        
        let chat_request = ChatRequest::from_user(prompt);
        
        let response = self.ai_client
            .exec_chat(
                &self.model, // Use Flash for fast, cost-effective analysis
                chat_request,
                Some(chat_options),
            )
            .await
            .map_err(|e| AppError::LlmClientError(format!("Flash-Lite item analysis failed: {}", e)))?;
        
        // Parse the structured response
        self.parse_structured_item_response(&response)
    }
    
    /// Parse structured AI response for item analysis
    fn parse_structured_item_response(
        &self,
        response: &ChatResponse,
    ) -> Result<Vec<ItemTimeline>, AppError> {
        // Extract text from ChatResponse
        let response_text = response.contents
            .iter()
            .find_map(|content| match content {
                MessageContent::Text(text) => Some(text.clone()),
                _ => None,
            })
            .ok_or_else(|| AppError::InternalServerErrorGeneric(
                "No text content found in AI response".to_string()
            ))?;
        
        // Parse as ItemAnalysisOutput
        let item_output: ItemAnalysisOutput = serde_json::from_str(&response_text)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to parse item analysis JSON: {}", e)))?;
        
        // Validate the output
        item_output.validate()?;
        
        // Convert to ItemTimeline vector
        Ok(item_output.to_item_timelines()?)
    }
    
    /// Filter item timelines based on query requirements
    async fn filter_item_timelines_by_query(
        &self,
        timelines: Vec<ItemTimeline>,
        _query: &HybridQuery,
    ) -> Result<Vec<ItemTimeline>, AppError> {
        // For now, return all timelines
        // In a more sophisticated implementation, this would filter based on query type and options
        Ok(timelines)
    }
    
    /// Prepare events data for item analysis
    async fn prepare_events_for_item_analysis(
        &self,
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut events_text = String::new();
        
        for (i, event) in events.iter().enumerate() {
            events_text.push_str(&format!("\n--- Event {} ---\n", i + 1));
            events_text.push_str(&format!("Summary: {}\n", event.summary));
            events_text.push_str(&format!("Type: {}\n", event.event_type));
            events_text.push_str(&format!("Timestamp: {}\n", event.timestamp_iso8601));
            
            if let Some(event_data) = &event.event_data {
                events_text.push_str(&format!("Event Data: {}\n", 
                    serde_json::to_string_pretty(event_data).unwrap_or_else(|_| "Invalid JSON".to_string())
                ));
            }
        }
        
        Ok(events_text)
    }
    
    /// Process a single item event and update item timeline
    fn process_item_event(
        &self,
        item_map: &mut HashMap<Uuid, ItemTimeline>,
        item_obj: &serde_json::Map<String, JsonValue>,
        event_id: Uuid,
        timestamp: DateTime<Utc>,
    ) -> Result<(), AppError> {
        let item_id = item_obj.get("item_id")
            .and_then(|id| id.as_str())
            .and_then(|id| Uuid::parse_str(id).ok())
            .ok_or_else(|| AppError::BadRequest("Invalid item_id in event".to_string()))?;
            
        let item_name = item_obj.get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("Unknown Item")
            .to_string();
            
        let action = item_obj.get("action")
            .and_then(|a| a.as_str())
            .unwrap_or("unknown");
            
        // Get or create item timeline
        let timeline = item_map.entry(item_id).or_insert_with(|| ItemTimeline {
            item_id,
            item_name: item_name.clone(),
            ownership_history: Vec::new(),
            usage_patterns: Vec::new(),
            current_owner: None,
            current_location: None,
            status: ItemStatus::Unknown,
        });
        
        // Update item name if more specific
        if timeline.item_name == "Unknown Item" && item_name != "Unknown Item" {
            timeline.item_name = item_name;
        }
        
        // Process action
        match action {
            "discovered" | "created" | "found" => {
                if let Some(owner) = item_obj.get("owner")
                    .and_then(|o| o.as_str())
                    .and_then(|o| Uuid::parse_str(o).ok()) {
                    
                    timeline.ownership_history.push(ItemOwnershipRecord {
                        owner_id: owner,
                        from_event_id: event_id,
                        from_timestamp: timestamp,
                        to_event_id: None,
                        to_timestamp: None,
                        acquisition_method: action.to_string(),
                    });
                    timeline.current_owner = Some(owner);
                    timeline.status = ItemStatus::Active;
                }
            }
            "transferred" => {
                // End previous ownership
                if let Some(from_owner) = item_obj.get("from_owner")
                    .and_then(|f| f.as_str())
                    .and_then(|f| Uuid::parse_str(f).ok()) {
                    
                    if let Some(last_record) = timeline.ownership_history.last_mut() {
                        if last_record.owner_id == from_owner && last_record.to_event_id.is_none() {
                            last_record.to_event_id = Some(event_id);
                            last_record.to_timestamp = Some(timestamp);
                        }
                    }
                }
                
                // Start new ownership
                if let Some(to_owner) = item_obj.get("to_owner")
                    .and_then(|t| t.as_str())
                    .and_then(|t| Uuid::parse_str(t).ok()) {
                    
                    timeline.ownership_history.push(ItemOwnershipRecord {
                        owner_id: to_owner,
                        from_event_id: event_id,
                        from_timestamp: timestamp,
                        to_event_id: None,
                        to_timestamp: None,
                        acquisition_method: "transferred".to_string(),
                    });
                    timeline.current_owner = Some(to_owner);
                }
            }
            "used" => {
                if let Some(user) = item_obj.get("user")
                    .or_else(|| item_obj.get("owner"))
                    .and_then(|u| u.as_str())
                    .and_then(|u| Uuid::parse_str(u).ok()) {
                    
                    let usage_type = item_obj.get("usage_type")
                        .and_then(|u| u.as_str())
                        .unwrap_or("generic")
                        .to_string();
                        
                    let context = item_obj.get("context")
                        .and_then(|c| c.as_str())
                        .map(|c| c.to_string());
                        
                    let effect = item_obj.get("effect")
                        .and_then(|e| e.as_str())
                        .map(|e| e.to_string());
                        
                    timeline.usage_patterns.push(ItemUsagePattern {
                        user_id: user,
                        event_id,
                        timestamp,
                        usage_type,
                        context,
                        effect,
                    });
                }
            }
            "placed" => {
                if let Some(location) = item_obj.get("location") {
                    if let Some(loc_name) = location.get("name")
                        .and_then(|n| n.as_str())
                        .or_else(|| location.as_str()) {
                        timeline.current_location = Some(loc_name.to_string());
                    }
                }
            }
            "moved" => {
                if let Some(to_location) = item_obj.get("to_location") {
                    if let Some(loc_name) = to_location.get("name")
                        .and_then(|n| n.as_str())
                        .or_else(|| to_location.as_str()) {
                        timeline.current_location = Some(loc_name.to_string());
                    }
                }
            }
            "destroyed" | "depleted" => {
                // End current ownership
                if let Some(last_record) = timeline.ownership_history.last_mut() {
                    if last_record.to_event_id.is_none() {
                        last_record.to_event_id = Some(event_id);
                        last_record.to_timestamp = Some(timestamp);
                    }
                }
                timeline.current_owner = None;
                timeline.status = if action == "depleted" {
                    ItemStatus::Depleted
                } else {
                    ItemStatus::Destroyed
                };
            }
            "lost" => {
                timeline.current_owner = None;
                timeline.current_location = None;
                timeline.status = ItemStatus::Lost;
            }
            _ => {
                // Generic action - just record usage
                if let Some(user) = item_obj.get("user")
                    .or_else(|| item_obj.get("owner"))
                    .and_then(|u| u.as_str())
                    .and_then(|u| Uuid::parse_str(u).ok()) {
                    
                    timeline.usage_patterns.push(ItemUsagePattern {
                        user_id: user,
                        event_id,
                        timestamp,
                        usage_type: action.to_string(),
                        context: None,
                        effect: None,
                    });
                }
            }
        }
        
        Ok(())
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

    /// Analyze relationship between two specific entities using AI-driven analysis
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
        
        // Use AI to analyze relationship instead of hardcoded logic
        let ai_analysis = self.analyze_relationship_with_ai(
            entity_a,
            entity_b,
            events,
            &current_relationship,
            &relationship_history
        ).await?;
        
        // Convert AI analysis to legacy RelationshipMetrics format for backward compatibility
        let metrics = RelationshipMetrics {
            stability: ai_analysis.relationship_metrics.stability,
            strength: ai_analysis.relationship_metrics.strength,
            trend: self.convert_ai_trend_to_legacy(&ai_analysis.relationship_metrics.trend),
            interaction_count: relationship_history.len(),
        };
        
        Ok(RelationshipAnalysis {
            from_entity_id: entity_a,
            to_entity_id: entity_b,
            current_relationship,
            relationship_history,
            analysis: metrics,
        })
    }
    
    /// Analyze relationship using AI with structured output
    async fn analyze_relationship_with_ai(
        &self,
        entity_a: Uuid,
        entity_b: Uuid,
        events: &[ChronicleEvent],
        current_relationship: &Option<RelationshipContext>,
        relationship_history: &[RelationshipHistoryEntry],
    ) -> Result<RelationshipAnalysisOutput, AppError> {
        // Prepare context for AI analysis
        let mut context_data = serde_json::json!({
            "entity_a_id": entity_a,
            "entity_b_id": entity_b,
            "events_count": events.len(),
            "relationship_history_count": relationship_history.len()
        });
        
        // Add current relationship data if available
        if let Some(current) = current_relationship {
            context_data["current_relationship"] = serde_json::json!({
                "relationship_type": current.relationship_type,
                "relationship_data": current.relationship_data
            });
        }
        
        // Add relationship history data
        context_data["relationship_history"] = serde_json::json!(
            relationship_history.iter().map(|entry| {
                serde_json::json!({
                    "timestamp": entry.timestamp,
                    "relationship_type": entry.relationship_type,
                    "relationship_data": entry.relationship_data,
                    "triggering_event": entry.triggering_event
                })
            }).collect::<Vec<_>>()
        );
        
        // Add relevant events for context
        context_data["relevant_events"] = serde_json::json!(
            events.iter().take(10).map(|event| {
                serde_json::json!({
                    "event_type": event.event_type,
                    "summary": event.summary,
                    "timestamp": event.timestamp_iso8601,
                    "actors": event.actors
                })
            }).collect::<Vec<_>>()
        );
        
        // Create AI prompt for relationship analysis
        let system_prompt = format!(
            "You are an expert relationship analyst specializing in analyzing complex relationships between entities based on historical events and interactions. Your task is to provide a comprehensive analysis of the relationship between two entities.

            Analyze the relationship between Entity A (ID: {}) and Entity B (ID: {}) based on the provided context data, events, and relationship history.

            Consider the following aspects in your analysis:
            1. **Relationship Type & Nature**: Identify the type of relationship (friendship, rivalry, family, professional, romantic, etc.) and its current nature
            2. **Power Dynamics**: Analyze the power balance, authority structures, and influence patterns
            3. **Communication Patterns**: Assess frequency, quality, directness, and conflict resolution styles
            4. **Emotional Dynamics**: Evaluate emotional intensity, valence, stability, and dominant emotions
            5. **Trust & Loyalty**: Measure trust levels, loyalty strength, reliability, and commitment factors
            6. **Relationship Metrics**: Calculate strength, stability, interaction frequency, quality, and mutual dependence
            7. **Historical Analysis**: Identify relationship phases, turning points, milestones, and patterns
            8. **Trend Analysis**: Determine relationship direction, trend strength, and predict future development

            Provide a comprehensive analysis with specific metrics, detailed explanations, and evidence-based insights.",
            entity_a, entity_b
        );
        
        let user_prompt = format!(
            "Analyze the relationship between these two entities based on the following context:

            Context Data:
            {}

            Please provide a detailed relationship analysis including:
            - Comprehensive relationship details with power dynamics, communication patterns, emotional dynamics, and trust/loyalty analysis
            - Quantitative metrics for strength, stability, interaction frequency, quality, and mutual dependence
            - Historical analysis with phases, turning points, milestones, and patterns
            - Trend analysis with direction, strength, confidence, and predictions
            - Overall confidence score and detailed justification

            Focus on evidence-based analysis using the provided events and relationship history. Ensure all numerical values are within their specified ranges (0.0-1.0 for most metrics, -1.0 to 1.0 for emotional valence).",
            serde_json::to_string_pretty(&context_data).unwrap_or_else(|_| "{}".to_string())
        );
        
        // Set up structured output
        let schema = get_relationship_analysis_schema();
        let chat_options = ChatOptions {
            response_format: Some(ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec {
                schema,
            })),
            ..Default::default()
        };
        
        let messages = vec![
            ChatMessage::system(&system_prompt),
            ChatMessage::user(MessageContent::Text(user_prompt)),
        ];
        
        let chat_request = ChatRequest::new(messages);
        
        // Use Flash-Lite for relationship analysis
        let ai_response = self.ai_client
            .exec_chat(&self.model, chat_request, Some(chat_options))
            .await?;
        
        // Parse the AI response
        let content = ai_response.first_content_text_as_str().unwrap_or("{}");
        let analysis: RelationshipAnalysisOutput = serde_json::from_str(content)
            .map_err(|e| AppError::BadRequest(format!("Failed to parse AI relationship analysis response: {}", e)))?;
        
        // Validate the analysis
        analysis.validate()?;
        
        debug!("AI relationship analysis completed for entities {} and {} with confidence {}", 
            entity_a, entity_b, analysis.confidence_score);
        
        Ok(analysis)
    }
    
    /// Convert AI trend direction to legacy RelationshipTrend enum
    fn convert_ai_trend_to_legacy(&self, ai_trend: &crate::services::agentic::relationship_analysis_structured_output::RelationshipTrendOutput) -> RelationshipTrend {
        match ai_trend.direction.as_str() {
            "improving" => RelationshipTrend::Improving,
            "declining" => RelationshipTrend::Declining,
            "stable" => RelationshipTrend::Stable,
            "volatile" => RelationshipTrend::Volatile,
            _ => RelationshipTrend::Unknown,
        }
    }

    /// Build basic entity contexts for fallback mode
    async fn build_basic_entity_contexts(
        &self,
        events: &[ChronicleEvent],
        query: &HybridQuery,
    ) -> Result<Vec<EntityTimelineContext>, AppError> {
        use std::collections::HashMap;
        
        let mut entity_map: HashMap<Uuid, EntityTimelineContext> = HashMap::new();
        
        // Extract entities mentioned in events
        for event in events {
            // Process actors in the event
            if let Some(actors) = &event.actors {
                if let Some(actors_array) = actors.as_array() {
                    for actor in actors_array {
                        if let Some(actor_obj) = actor.as_object() {
                            if let Some(entity_id) = actor_obj.get("entity_id")
                                .and_then(|id| id.as_str())
                                .and_then(|id| Uuid::parse_str(id).ok()) {
                                
                                // Get or create entity context
                                let entity_context = entity_map.entry(entity_id).or_insert_with(|| {
                                    EntityTimelineContext {
                                        entity_id,
                                        entity_name: actor_obj.get("context")
                                            .and_then(|c| c.as_str())
                                            .map(|s| s.to_string()),
                                        current_state: None,
                                        timeline_events: Vec::new(),
                                        relationships: Vec::new(),
                                        relevance_score: 1.0, // Default relevance for fallback mode
                                        extracted_context: ExtractedEntityContext::default(),
                                        item_interactions: Vec::new(),
                                    }
                                });
                                
                                // Add this event to the entity's timeline
                                entity_context.timeline_events.push(TimelineEvent {
                                    event: event.clone(),
                                    entity_state_at_time: None, // No state info in fallback mode
                                    co_participants: Vec::new(), // Could be extracted from other actors
                                    significance_score: 1.0, // Default significance
                                });
                            }
                        }
                    }
                }
            }
            
            // Also check for entity references in the event summary
            // This is a simple heuristic for when actors aren't properly structured
            if entity_map.is_empty() && !event.summary.is_empty() {
                // Try to extract entity names from the summary
                // This is a fallback for events without proper actor data
                debug!("No actors found in event {}, checking summary for entity names", event.id);
            }
        }
        
        // Convert map to vector and sort by relevance/timeline
        let mut contexts: Vec<EntityTimelineContext> = entity_map.into_values().collect();
        
        // Sort by number of events (most active entities first)
        contexts.sort_by(|a, b| b.timeline_events.len().cmp(&a.timeline_events.len()));
        
        // Apply any query-specific filtering
        if let HybridQueryType::EntityTimeline { entity_id: Some(target_id), .. } = &query.query_type {
            contexts.retain(|ctx| ctx.entity_id == *target_id);
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
            // Item query types
            HybridQueryType::ItemTimeline => {
                key_insights.push(format!("Tracked ownership history across {} events", events.len()));
            }
            HybridQueryType::ItemUsage => {
                key_insights.push(format!("Analyzed item usage patterns from {} events", events.len()));
            }
            HybridQueryType::ItemLocation => {
                key_insights.push(format!("Tracked item locations across {} events", events.len()));
            }
            HybridQueryType::ItemLifecycle => {
                key_insights.push(format!("Analyzed item lifecycle through {} events", events.len()));
            }
            HybridQueryType::ItemInteractions => {
                key_insights.push(format!("Found {} entities interacting with items", entities.len()));
            }
            HybridQueryType::ItemSearch => {
                key_insights.push(format!("Found items matching search criteria in {} events", events.len()));
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

        // Generate narrative answer based on query results
        let narrative_answer = self.generate_narrative_answer(
            entities,
            events,
            relationships,
            query
        ).await?;

        Ok(HybridQuerySummary {
            entities_found: entities.len(),
            events_analyzed: events.len(),
            relationships_found: relationships.len(),
            key_insights,
            narrative_answer: Some(narrative_answer),
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
        
        // Build item timelines if this is an item query
        let item_timelines = if self.is_item_query(&query.query_type) {
            self.build_item_timelines(&chronicle_events, query).await?
        } else {
            Vec::new()
        };

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
            item_timelines,
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
                
                // Note: Relationship turning points are now analyzed by AI
                // This provides more contextual and intelligent analysis
                // compared to the previous hardcoded approach
                
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

    /// Calculate entity relevance score based on query and entity context using AI analysis
    async fn calculate_entity_relevance_score(
        &self,
        entity_id: Uuid,
        timeline_events: &[TimelineEvent],
        current_state: &Option<EntityStateSnapshot>,
        query: &HybridQuery,
    ) -> Result<f32, AppError> {
        use crate::services::agentic::query_relevance_structured_output::{
            get_query_relevance_schema, QueryRelevanceOutput
        };
        use genai::chat::{ChatRequest, ChatOptions, ChatResponseFormat, JsonSchemaSpec, MessageContent};
        
        debug!("Calculating entity relevance score for {} using AI", entity_id);
        
        // Build comprehensive context for AI analysis
        let entity_name = self.extract_entity_name(entity_id).await?.unwrap_or_else(|| "Unknown Entity".to_string());
        
        // Build query context
        let query_context = match &query.query_type {
            HybridQueryType::NarrativeQuery { query_text, .. } => {
                format!("Narrative Query: {}", query_text)
            }
            HybridQueryType::RelationshipHistory { entity_a, entity_b, .. } => {
                format!("Relationship History Query: Between {} and {}", entity_a, entity_b)
            }
            HybridQueryType::LocationQuery { location_name, .. } => {
                format!("Location Query: Entities at {}", location_name)
            }
            HybridQueryType::EntityTimeline { entity_name, .. } => {
                format!("Entity Timeline Query: History of {}", entity_name)
            }
            HybridQueryType::EventParticipants { event_description, .. } => {
                format!("Event Participants Query: Who was involved in {}", event_description)
            }
            HybridQueryType::EntityStateAtTime { entity_id, timestamp, .. } => {
                format!("Entity State Query: State of {} at {}", entity_id, timestamp)
            }
            HybridQueryType::ItemTimeline => {
                format!("Item Timeline Query: Track ownership history of an item")
            }
            HybridQueryType::ItemUsage => {
                format!("Item Usage Query: Show item usage patterns")
            }
            HybridQueryType::ItemLocation => {
                format!("Item Location Query: Where has this item been?")
            }
            HybridQueryType::ItemLifecycle => {
                format!("Item Lifecycle Query: Track item lifecycle from creation to destruction")
            }
            HybridQueryType::ItemInteractions => {
                format!("Item Interactions Query: Who has interacted with this item?")
            }
            HybridQueryType::ItemSearch => {
                format!("Item Search Query: Find items matching criteria")
            }
            HybridQueryType::CausalChain { from_event, to_entity, .. } => {
                format!("Causal Chain Query: Trace causal chain from {:?} to {:?}", from_event, to_entity)
            }
            HybridQueryType::TemporalPath { entity_id, from_time, to_time, .. } => {
                format!("Temporal Path Query: Entity {} changes from {} to {}", entity_id, from_time, to_time)
            }
            HybridQueryType::RelationshipNetwork { center_entity_id, depth, .. } => {
                format!("Relationship Network Query: Network around {} with depth {}", center_entity_id, depth)
            }
            HybridQueryType::CausalInfluences { entity_id, time_window, .. } => {
                format!("Causal Influences Query: Influences on {} within {:?}", entity_id, time_window)
            }
            HybridQueryType::WorldModelSnapshot { timestamp, focus_entities, .. } => {
                format!("World Model Snapshot Query: Snapshot at {:?} focusing on {:?}", timestamp, focus_entities)
            }
        };
        
        // Build entity state context
        let state_context = if let Some(state) = current_state {
            let mut context = String::from("Current State Components:\n");
            for (component_type, data) in &state.components {
                context.push_str(&format!("- {}: {}\n", component_type, 
                    serde_json::to_string(data).unwrap_or_else(|_| data.to_string())));
            }
            context.push_str(&format!("\nStatus Indicators: {:?}\n", state.status_indicators));
            context.push_str(&format!("Snapshot Time: {}", state.snapshot_time));
            context
        } else {
            "No current state available".to_string()
        };
        
        // Build timeline context
        let timeline_context = if !timeline_events.is_empty() {
            let mut context = format!("Recent Timeline Events ({} total):\n", timeline_events.len());
            for (i, event) in timeline_events.iter().take(5).enumerate() {
                context.push_str(&format!("{}. {} - {} (significance: {:.2})\n", 
                    i + 1, 
                    event.event.timestamp_iso8601,
                    event.event.summary,
                    event.significance_score
                ));
                if !event.co_participants.is_empty() {
                    context.push_str(&format!("   Co-participants: {} entities\n", event.co_participants.len()));
                }
            }
            if timeline_events.len() > 5 {
                context.push_str(&format!("... and {} more events\n", timeline_events.len() - 5));
            }
            context
        } else {
            "No timeline events available".to_string()
        };
        
        let prompt = format!(
            r#"Analyze the relevance of this entity to the given query using multi-factor analysis.

Query Context:
{}

Entity Information:
- Entity ID: {}
- Entity Name: {}

{}

{}

Instructions:
1. Analyze entity name relevance - how well does the entity name match what the query is looking for?
2. Analyze current state relevance - does the entity's current state (components, status) match query needs?
3. Analyze timeline relevance - do the entity's past events relate to the query?
4. Analyze semantic relevance - what deeper contextual connections exist?
5. Analyze query type relevance - how relevant is this entity to this specific type of query?
6. Analyze temporal relevance - consider recency and time period alignment

For each factor:
- Provide a score (0.0-1.0)
- Assign an appropriate weight based on the query type
- Explain your reasoning
- List specific evidence

Weights should sum to approximately 1.0 and reflect the relative importance of each factor for this specific query.

Return a comprehensive relevance analysis with an overall weighted score and natural language explanation."#,
            query_context,
            entity_id,
            entity_name,
            state_context,
            timeline_context
        );
        
        // Get the JSON schema for structured output
        let schema = get_query_relevance_schema();
        
        // Create chat request with structured output
        let chat_options = ChatOptions::default()
            .with_temperature(0.2) // Low temperature for consistent scoring
            .with_response_format(ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec {
                schema: schema.clone(),
            }));
        
        let messages = vec![
            ChatMessage::system("You are an expert relevance scoring analyst. Evaluate how relevant entities are to queries based on multiple factors."),
            ChatMessage::user(MessageContent::Text(prompt)),
        ];
        
        let chat_request = ChatRequest::new(messages);
        
        let response = self.ai_client.exec_chat(&self.model, chat_request, Some(chat_options)).await
            .map_err(|e| AppError::AiServiceError(format!("Failed to analyze query relevance: {}", e)))?;
        
        // Parse the structured response
        let content = response.contents
            .first()
            .and_then(|c| match c {
                MessageContent::Text(text) => Some(text.clone()),
                _ => None,
            })
            .ok_or_else(|| AppError::AiServiceError("No content in relevance analysis response".to_string()))?;
        
        let relevance_output: QueryRelevanceOutput = serde_json::from_str(&content)
            .map_err(|e| AppError::AiServiceError(format!("Failed to parse relevance analysis: {}", e)))?;
        
        // Validate the output
        relevance_output.validate()?;
        
        // Log detailed analysis
        debug!("Entity {} relevance analysis (confidence: {:.2}):", entity_id, relevance_output.confidence_score);
        debug!("  - Entity Name: {:.2} (weight: {:.2})", 
               relevance_output.entity_name_relevance.score,
               relevance_output.entity_name_relevance.weight);
        debug!("  - Current State: {:.2} (weight: {:.2})", 
               relevance_output.current_state_relevance.score,
               relevance_output.current_state_relevance.weight);
        debug!("  - Timeline: {:.2} (weight: {:.2})", 
               relevance_output.timeline_relevance.score,
               relevance_output.timeline_relevance.weight);
        debug!("  - Semantic: {:.2} (weight: {:.2})", 
               relevance_output.semantic_relevance.score,
               relevance_output.semantic_relevance.weight);
        debug!("  - Query Type: {:.2} (weight: {:.2})", 
               relevance_output.query_type_relevance.score,
               relevance_output.query_type_relevance.weight);
        debug!("  - Temporal: {:.2} (weight: {:.2})", 
               relevance_output.temporal_relevance.score,
               relevance_output.temporal_relevance.weight);
        debug!("  Overall Score: {:.3}", relevance_output.overall_relevance_score);
        debug!("  Explanation: {}", relevance_output.relevance_explanation);
        
        Ok(relevance_output.overall_relevance_score)
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

    /// Calculate event significance score using AI-driven multi-factor analysis
    pub async fn calculate_event_significance(&self, entity_id: Uuid, event: &ChronicleEvent) -> Result<f32, AppError> {
        use crate::services::agentic::event_significance_structured_output::{
            get_event_significance_schema, EventSignificanceOutput
        };
        use genai::chat::{ChatRequest, ChatOptions, ChatResponseFormat, JsonSchemaSpec, MessageContent};
        
        debug!("Calculating event significance for {} using AI", entity_id);
        
        // Get entity name for better context
        let entity_name = self.extract_entity_name(entity_id).await?.unwrap_or_else(|| "Unknown Entity".to_string());
        
        // Get co-participants for social context
        let co_participants = self.extract_co_participants(entity_id, event).await?;
        let participant_count = co_participants.len() + 1; // +1 for the entity itself
        
        // Calculate event age for temporal context
        let now = chrono::Utc::now();
        let event_age = now.signed_duration_since(event.created_at);
        let hours_ago = event_age.num_hours();
        
        // Build comprehensive event context
        let event_context = format!(
            "Event Details:
- Event ID: {}
- Event Type: {}
- Summary: {}
- Created: {} ({} hours ago)
- Participant Count: {}
- Event Data: {}

Entity Information:
- Entity ID: {}
- Entity Name: {}
- Co-participants: {} entities

Analysis Focus:
Analyze the significance of this event for the specified entity considering:
1. Event type and inherent importance
2. Entity's role and involvement level
3. Event complexity and information richness
4. Temporal relevance and recency
5. Social context and participant network
6. Narrative impact and world-building value",
            event.id,
            event.event_type,
            event.summary,
            event.created_at,
            hours_ago,
            participant_count,
            event.event_data.as_ref().map(|d| d.to_string()).unwrap_or_else(|| "None".to_string()),
            entity_id,
            entity_name,
            co_participants.len()
        );
        
        let system_prompt = format!(
            r#"You are an expert narrative analyst specializing in event significance assessment. 
            Your task is to analyze chronicle events and determine their significance for specific entities 
            using comprehensive multi-factor analysis.

Your analysis should consider:

1. **Event Type Impact**: Inherent significance of the event type (combat, discovery, death, etc.)
2. **Entity Role**: The entity's level of involvement, agency, and impact in the event
3. **Complexity Assessment**: Information density, narrative complexity, and descriptive quality
4. **Temporal Relevance**: Recency effects and time-sensitive factors
5. **Social Significance**: Network effects, participant count, and relationship impacts
6. **Narrative Impact**: Plot progression, character development, and world-building value

For each factor:
- Provide a score (0.0-1.0) representing the factor's contribution
- Assign an appropriate weight based on the event type and context
- Include specific evidence from the event data
- Explain your reasoning with confidence levels

The overall significance should reflect the event's importance to the entity's story,
considering both immediate impact and long-term consequences.

Significance Categories:
- Critical (0.8-1.0): Life-changing, world-altering events
- High (0.6-0.8): Important events with major consequences
- Medium (0.4-0.6): Notable events with moderate impact
- Low (0.2-0.4): Minor events with limited significance
- Minimal (0.0-0.2): Routine or inconsequential events

OUTPUT FORMAT:
Return a structured JSON analysis following the exact schema provided."#
        );
        
        let user_prompt = format!(
            "Analyze the significance of this event for the specified entity. \
            Consider all factors comprehensively and provide detailed reasoning \
            for your assessment. Focus on the entity's perspective and involvement.\n\n{}",
            event_context
        );
        
        // Get schema for structured output
        let schema = get_event_significance_schema();
        
        // Configure AI client for structured output
        let chat_options = ChatOptions::default()
            .with_temperature(0.3)
            .with_response_format(ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec {
                schema: schema.clone(),
            }));
        
        // Create chat request with structured output
        let messages = vec![
            ChatMessage::system(&system_prompt),
            ChatMessage::user(MessageContent::Text(user_prompt)),
        ];
        
        let chat_request = ChatRequest::new(messages);
        
        // Call AI service with Flash-Lite for efficiency
        let ai_response = self.ai_client
            .exec_chat(&self.model, chat_request, Some(chat_options))
            .await?;
        
        // Parse the structured response
        let content = ai_response.contents
            .first()
            .and_then(|c| match c {
                MessageContent::Text(text) => Some(text.clone()),
                _ => None,
            })
            .ok_or_else(|| AppError::AiServiceError("No content in event significance response".to_string()))?;
        
        let significance_output: EventSignificanceOutput = 
            serde_json::from_str(&content)
                .map_err(|e| AppError::AiServiceError(format!("Failed to parse event significance: {}", e)))?;
        
        // Validate the output
        significance_output.validate()?;
        
        tracing::debug!(
            "Event {} significance for entity {} ({}): {:.3} (confidence: {:.2}) - {}",
            event.id,
            entity_id,
            entity_name,
            significance_output.overall_significance,
            significance_output.confidence_score,
            significance_output.get_significance_category()
        );
        
        // Log top contributing factors
        let top_factors = significance_output.get_top_factors(3);
        for (i, factor) in top_factors.iter().enumerate() {
            debug!("  Factor {}: {} = {:.3} (weight: {:.2}, contribution: {:.3})",
                   i + 1,
                   factor.factor_name,
                   factor.factor_score,
                   factor.factor_weight,
                   factor.weighted_contribution
            );
        }
        
        Ok(significance_output.overall_significance)
    }


    /// Reconstruct entity state at the time of a specific event using AI analysis
    async fn reconstruct_entity_state_at_event(
        &self,
        entity_id: Uuid,
        event: &ChronicleEvent,
        user_id: Uuid,
    ) -> Result<Option<EntityStateSnapshot>, AppError> {
        use genai::chat::{ChatOptions, ChatResponseFormat, JsonSchemaSpec};
        use crate::services::agentic::historical_state_reconstruction_structured_output::{
            HistoricalStateReconstructionOutput, get_historical_state_reconstruction_schema
        };
        
        // Get current state and historical events for context
        let current_state = self.get_entity_current_state(entity_id, user_id).await.ok();
        let events_after = self.get_events_after_timestamp(entity_id, event.created_at).await?;
        let events_before = self.get_events_before_timestamp(entity_id, event.created_at).await?;
        
        // Prepare context for AI analysis
        let current_state_context = if let Some(ref state) = current_state {
            serde_json::to_string_pretty(state).unwrap_or_else(|_| "Unable to serialize current state".to_string())
        } else {
            "No current state available".to_string()
        };
        
        let events_context = format!(
            "Target Event: {}\nEvents Before (last 10): {}\nEvents After (first 10): {}",
            serde_json::to_string_pretty(event).unwrap_or_else(|_| "Unable to serialize event".to_string()),
            events_before.iter().rev().take(10).map(|e| 
                serde_json::to_string_pretty(e).unwrap_or_else(|_| "Unable to serialize event".to_string())
            ).collect::<Vec<_>>().join("\n---\n"),
            events_after.iter().take(10).map(|e| 
                serde_json::to_string_pretty(e).unwrap_or_else(|_| "Unable to serialize event".to_string())
            ).collect::<Vec<_>>().join("\n---\n")
        );
        
        // Create AI prompt for historical state reconstruction
        let system_prompt = format!(
            "You are an expert at reconstructing historical entity states from chronicle events. \
            Your task is to analyze events and determine what the entity's state was at a specific point in time.

            ENTITY CONTEXT:
            - Entity ID: {}
            - Target Timestamp: {}
            - Current State: {}
            
            EVENTS CONTEXT:
            {}
            
            INSTRUCTIONS:
            1. Analyze the target event and surrounding events to identify state changes
            2. Determine what the entity's state was at the time of the target event
            3. Use backward reconstruction from current state or forward reconstruction from available data
            4. Consider component changes like health, location, inventory, status, relationships
            5. Provide confidence scores and evidence for your analysis
            6. Identify any limitations or uncertainty factors in the reconstruction
            
            OUTPUT FORMAT:
            Return a structured JSON analysis following the exact schema provided.",
            entity_id,
            event.created_at,
            current_state_context,
            events_context
        );
        
        let user_prompt = format!(
            "Reconstruct the entity state at the time of the target event. \
            Focus on identifying what state changes occurred and what the entity's \
            complete state was at that moment. Use all available context to make \
            the most accurate reconstruction possible."
        );
        
        // Get schema for structured output
        let schema = get_historical_state_reconstruction_schema();
        
        // Configure AI client for structured output
        let chat_options = ChatOptions::default()
            .with_temperature(0.2)
            .with_response_format(ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec {
                schema: schema.clone(),
            }));
        
        // Create chat request with structured output
        let messages = vec![
            ChatMessage::system(&system_prompt),
            ChatMessage::user(MessageContent::Text(user_prompt)),
        ];
        
        let chat_request = ChatRequest::new(messages);
        
        // Call AI service with Flash-Lite for efficiency
        let ai_response = self.ai_client
            .exec_chat(&self.model, chat_request, Some(chat_options))
            .await?;
        
        // Parse the structured response
        let content = ai_response.contents
            .first()
            .and_then(|c| match c {
                MessageContent::Text(text) => Some(text.clone()),
                _ => None,
            })
            .ok_or_else(|| AppError::AiServiceError("No content in historical state reconstruction response".to_string()))?;
        
        let reconstruction_output: HistoricalStateReconstructionOutput = 
            serde_json::from_str(&content)
                .map_err(|e| AppError::AiServiceError(format!("Failed to parse historical state reconstruction: {}", e)))?;
        
        // Validate the output
        reconstruction_output.validate()?;
        
        // Convert AI analysis to EntityStateSnapshot
        let snapshot = self.convert_reconstruction_to_snapshot(
            entity_id,
            event.created_at,
            &reconstruction_output,
            current_state.as_ref()
        ).await?;
        
        tracing::debug!(
            "Historical state reconstruction completed for entity {} at {}: confidence={:.2}, quality={:.2}",
            entity_id,
            event.created_at,
            reconstruction_output.reconstruction_confidence,
            reconstruction_output.calculate_quality_score()
        );
        
        Ok(Some(snapshot))
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
    
    /// Get chronicle events before a specific timestamp for an entity
    async fn get_events_before_timestamp(
        &self,
        entity_id: Uuid,
        timestamp: DateTime<Utc>,
    ) -> Result<Vec<ChronicleEvent>, AppError> {
        use diesel::prelude::*;
        use crate::schema::chronicle_events;
        
        let conn = self.db_pool.get().await?;
        
        // Query for events before the timestamp where entity is involved
        let events = conn
            .interact(move |conn| {
                chronicle_events::table
                    .filter(chronicle_events::created_at.lt(timestamp))
                    .order(chronicle_events::created_at.desc())
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
    
    /// Convert AI reconstruction output to EntityStateSnapshot
    async fn convert_reconstruction_to_snapshot(
        &self,
        entity_id: Uuid,
        timestamp: DateTime<Utc>,
        reconstruction: &crate::services::agentic::historical_state_reconstruction_structured_output::HistoricalStateReconstructionOutput,
        current_state: Option<&EntityStateSnapshot>,
    ) -> Result<EntityStateSnapshot, AppError> {
        use std::collections::HashMap;
        
        // Start with current state if available, otherwise create empty snapshot
        let mut snapshot = if let Some(current) = current_state {
            current.clone()
        } else {
            EntityStateSnapshot {
                entity_id,
                archetype_signature: "unknown".to_string(),
                components: HashMap::new(),
                snapshot_time: timestamp,
                status_indicators: Vec::new(),
            }
        };
        
        // Update with reconstructed state from AI
        snapshot.entity_id = entity_id;
        snapshot.snapshot_time = timestamp;
        snapshot.components = reconstruction.reconstructed_state.components.clone();
        snapshot.status_indicators = reconstruction.reconstructed_state.status_indicators.clone();
        
        // Use archetype signature from AI if available
        if let Some(ref archetype) = reconstruction.reconstructed_state.archetype_signature {
            snapshot.archetype_signature = archetype.clone();
        }
        
        // Add reconstruction metadata as a special component
        let mut reconstruction_metadata = HashMap::new();
        reconstruction_metadata.insert("confidence".to_string(), 
            serde_json::Value::Number(serde_json::Number::from_f64(reconstruction.reconstruction_confidence as f64).unwrap()));
        reconstruction_metadata.insert("quality_score".to_string(), 
            serde_json::Value::Number(serde_json::Number::from_f64(reconstruction.calculate_quality_score() as f64).unwrap()));
        reconstruction_metadata.insert("reconstruction_method".to_string(), 
            serde_json::Value::String(reconstruction.reconstruction_analysis.reconstruction_method.clone()));
        reconstruction_metadata.insert("events_analyzed".to_string(), 
            serde_json::Value::Number(serde_json::Number::from(reconstruction.reconstruction_analysis.events_analyzed)));
        reconstruction_metadata.insert("uncertainty_factors".to_string(), 
            serde_json::Value::Array(reconstruction.reconstructed_state.uncertainty_factors.iter()
                .map(|f| serde_json::Value::String(f.clone())).collect()));
        
        snapshot.components.insert("_reconstruction_metadata".to_string(), 
            serde_json::Value::Object(reconstruction_metadata.into_iter().collect()));
        
        Ok(snapshot)
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
                if let Some(_new_location) = location_change.as_str() {
                    state_changes.push(StateChange {
                        component_type: "position".to_string(),
                        change_type: "set".to_string(),
                        change_value: 0.0,
                        field_name: "location".to_string(),
                    });
                }
            }
            
            if let Some(inventory_change) = event_data.get("inventory_change") {
                if let Some(_item_added) = inventory_change.get("added") {
                    state_changes.push(StateChange {
                        component_type: "inventory".to_string(),
                        change_type: "add_item".to_string(),
                        change_value: 1.0,
                        field_name: "items".to_string(),
                    });
                }
                if let Some(_item_removed) = inventory_change.get("removed") {
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
                        // Reverse item addition by removing last item
                        if let Some(items) = component.get_mut(&change.field_name).and_then(|v| v.as_array_mut()) {
                            items.pop();
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

    /// Get user ID from events (helper method)
    fn get_user_id_from_events(&self, events: &[ChronicleEvent]) -> Option<Uuid> {
        events.first().map(|event| event.user_id)
    }


    /// Generate narrative answer from query results
    async fn generate_narrative_answer(
        &self,
        entities: &[EntityTimelineContext],
        events: &[ChronicleEvent],
        relationships: &[RelationshipAnalysis],
        query: &HybridQuery,
    ) -> Result<String, AppError> {
        debug!("Generating AI-driven narrative answer for query type: {:?}", query.query_type);

        // If we have no data, return a default response
        if entities.is_empty() && events.is_empty() && relationships.is_empty() {
            return Ok("No relevant information found for your query.".to_string());
        }

        // Generate narrative using AI with structured output
        let narrative_output = self.generate_narrative_with_ai(entities, events, relationships, query).await?;
        
        // Generate the final narrative text from the structured output
        let final_narrative = narrative_output.generate_final_narrative();
        
        debug!("Generated narrative answer with quality assessment: {}", 
               narrative_output.get_quality_assessment());

        Ok(final_narrative)
    }

    /// Generate narrative using AI with structured output
    async fn generate_narrative_with_ai(
        &self,
        entities: &[EntityTimelineContext],
        events: &[ChronicleEvent],
        relationships: &[RelationshipAnalysis],
        query: &HybridQuery,
    ) -> Result<NarrativeGenerationOutput, AppError> {
        debug!("Generating AI-driven narrative for query: {:?}", query.query_type);

        // Prepare context data for AI analysis
        let context_data = self.prepare_narrative_context_data(entities, events, relationships, query).await?;
        
        // Create AI prompt for narrative generation
        let system_prompt = self.build_narrative_generation_prompt(query, &context_data).await?;
        
        // Create chat request with structured output
        let schema = get_narrative_generation_schema();
        let chat_options = ChatOptions {
            response_format: Some(ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec {
                schema,
            })),
            ..Default::default()
        };

        let chat_request = ChatRequest::new(vec![
            ChatMessage {
                role: ChatRole::System,
                content: MessageContent::Text(system_prompt),
                options: None,
            },
            ChatMessage {
                role: ChatRole::User,
                content: MessageContent::Text(context_data),
                options: None,
            },
        ]);

        // Make AI request - use Flash-Lite model for narrative generation
        let response = self.ai_client.exec_chat(
            &self.model,
            chat_request,
            Some(chat_options),
        ).await
        .map_err(|e| AppError::BadRequest(format!("AI narrative generation failed: {}", e)))?;

        // Parse AI response
        let response_text = response.first_content_text_as_str().unwrap_or_default();
        
        let narrative_output: NarrativeGenerationOutput = serde_json::from_str(&response_text)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse AI narrative response: {}", e)))?;

        // Validate the output
        narrative_output.validate()?;

        debug!("AI narrative generation completed with confidence: {:.2}", narrative_output.confidence_score);

        Ok(narrative_output)
    }

    /// Prepare context data for AI narrative generation
    async fn prepare_narrative_context_data(
        &self,
        entities: &[EntityTimelineContext],
        events: &[ChronicleEvent],
        relationships: &[RelationshipAnalysis],
        query: &HybridQuery,
    ) -> Result<String, AppError> {
        let mut context = String::new();
        
        // Add query context
        context.push_str(&format!("Query Type: {:?}\n", query.query_type));
        context.push_str(&format!("User ID: {}\n", query.user_id));
        context.push_str(&format!("Chronicle ID: {:?}\n", query.chronicle_id));
        context.push_str(&format!("Max Results: {}\n", query.max_results));
        context.push_str(&format!("Include Current State: {}\n", query.include_current_state));
        context.push_str(&format!("Include Relationships: {}\n", query.include_relationships));
        context.push_str("\n");

        // Add entities context
        if !entities.is_empty() {
            context.push_str(&format!("Entities ({} total):\n", entities.len()));
            for (i, entity) in entities.iter().take(10).enumerate() {
                let name = entity.entity_name.as_ref().map(|s| s.as_str()).unwrap_or("Unknown Entity");
                context.push_str(&format!("{}. {} (Relevance: {:.2})\n", i + 1, name, entity.relevance_score));
                
                // Add current state if available
                if let Some(current_state) = &entity.current_state {
                    context.push_str(&format!("   Current State: {} components\n", current_state.components.len()));
                }
                
                // Add timeline events
                if !entity.timeline_events.is_empty() {
                    context.push_str(&format!("   Timeline Events: {}\n", entity.timeline_events.len()));
                    for (j, timeline_event) in entity.timeline_events.iter().take(3).enumerate() {
                        context.push_str(&format!("     {}. {} - {}\n", 
                                                j + 1, 
                                                timeline_event.event.event_type, 
                                                timeline_event.event.summary));
                    }
                }
            }
            context.push_str("\n");
        }

        // Add events context
        if !events.is_empty() {
            context.push_str(&format!("Events ({} total):\n", events.len()));
            for (i, event) in events.iter().take(10).enumerate() {
                context.push_str(&format!("{}. {} - {} ({})\n", 
                                        i + 1, 
                                        event.event_type, 
                                        event.summary, 
                                        event.created_at.format("%Y-%m-%d %H:%M")));
                
                // Add event data if available
                if let Some(data) = &event.event_data {
                    context.push_str(&format!("   Data: {}\n", data.to_string()));
                }
            }
            context.push_str("\n");
        }

        // Add relationships context
        if !relationships.is_empty() {
            context.push_str(&format!("Relationships ({} total):\n", relationships.len()));
            for (i, relationship) in relationships.iter().take(5).enumerate() {
                context.push_str(&format!("{}. Strength: {:.2}, Trend: {:?}\n", 
                                        i + 1, 
                                        relationship.analysis.strength, 
                                        relationship.analysis.trend));
            }
            context.push_str("\n");
        }

        Ok(context)
    }

    /// Build AI prompt for narrative generation
    async fn build_narrative_generation_prompt(
        &self,
        query: &HybridQuery,
        context_data: &str,
    ) -> Result<String, AppError> {
        let query_type_description = match &query.query_type {
            HybridQueryType::EntityTimeline { entity_name, .. } => {
                format!("Generate a comprehensive timeline narrative for entity: {}", entity_name)
            }
            HybridQueryType::EventParticipants { event_description, .. } => {
                format!("Generate a narrative about participants in event: {}", event_description)
            }
            HybridQueryType::RelationshipHistory { entity_a, entity_b, .. } => {
                format!("Generate a narrative about the relationship history between: {} and {}", entity_a, entity_b)
            }
            HybridQueryType::LocationQuery { location_name, .. } => {
                format!("Generate a narrative about location: {}", location_name)
            }
            HybridQueryType::NarrativeQuery { query_text, .. } => {
                format!("Generate a narrative response to: {}", query_text)
            }
            HybridQueryType::EntityStateAtTime { entity_id, timestamp, .. } => {
                format!("Generate a narrative about entity {} at time {}", entity_id, timestamp)
            }
            HybridQueryType::CausalChain { from_event, to_entity, .. } => {
                match (from_event, to_entity) {
                    (Some(event_id), Some(entity_id)) => format!("Generate a narrative about causal chain from event {} to entity {}", event_id, entity_id),
                    (Some(event_id), None) => format!("Generate a narrative about causal chain from event {}", event_id),
                    (None, Some(entity_id)) => format!("Generate a narrative about causal chain affecting entity {}", entity_id),
                    (None, None) => "Generate a narrative about causal chain analysis".to_string(),
                }
            }
            HybridQueryType::TemporalPath { entity_id, .. } => {
                format!("Generate a narrative about temporal path for entity: {}", entity_id)
            }
            HybridQueryType::RelationshipNetwork { center_entity_id, .. } => {
                format!("Generate a narrative about relationship network centered on: {}", center_entity_id)
            }
            HybridQueryType::CausalInfluences { entity_id, .. } => {
                format!("Generate a narrative about causal influences for entity: {}", entity_id)
            }
            HybridQueryType::WorldModelSnapshot { .. } => {
                "Generate a narrative about the current world model snapshot".to_string()
            }
            HybridQueryType::ItemTimeline => {
                "Generate a narrative about item timeline".to_string()
            }
            HybridQueryType::ItemUsage => {
                "Generate a narrative about item usage".to_string()
            }
            HybridQueryType::ItemLocation => {
                "Generate a narrative about item location".to_string()
            }
            HybridQueryType::ItemLifecycle => {
                "Generate a narrative about item lifecycle".to_string()
            }
            HybridQueryType::ItemInteractions => {
                "Generate a narrative about item interactions".to_string()
            }
            HybridQueryType::ItemSearch => {
                "Generate a narrative about item search results".to_string()
            }
        };

        let prompt = format!(
            r#"You are an expert narrative generator for the Sanguine Scribe Living World system. Your task is to create engaging, informative, and well-structured narrative responses based on the provided data.

Task: {}

Instructions:
1. Create a comprehensive narrative that addresses the specific query type and user request
2. Use the provided context data to inform your narrative, but don't just list facts - weave them into a coherent story
3. Structure your response with clear sections and logical flow
4. Ensure the narrative is engaging and readable while being informative
5. Include relevant details from entities, events, and relationships when available
6. Maintain consistency with the established world and character information
7. Use appropriate tone and style for the context (formal, conversational, analytical, etc.)
8. Provide supporting details and evidence for your narrative claims
9. Include a clear opening statement and conclusion
10. Assess the quality of your narrative across multiple dimensions

Quality Requirements:
- Clarity: The narrative should be easy to understand and follow
- Completeness: Cover all relevant aspects of the query
- Engagement: Keep the reader interested throughout
- Accuracy: Ensure all information is faithful to the provided context
- Readability: Use appropriate language and structure
- Cohesion: Maintain logical flow and connections between ideas
- Information Density: Balance detail with readability

Context Data:
{}"#,
            query_type_description,
            context_data
        );

        Ok(prompt)
    }

    // NOTE: All hardcoded narrative generation methods below have been replaced with AI-driven generation
    // They are kept for reference but are no longer called from generate_narrative_answer
    
    /// Generate narrative for entity timeline queries (DEPRECATED: Now uses AI)
    #[allow(dead_code)]
    async fn generate_entity_timeline_narrative(
        &self,
        entity_name: &str,
        entities: &[EntityTimelineContext],
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        // If we have no entity contexts but have chronicle events, generate narrative from events
        if entities.is_empty() && !events.is_empty() {
            // Filter events that involve this entity
            let entity_events: Vec<&ChronicleEvent> = events.iter()
                .filter(|event| {
                    // Check if entity is mentioned in summary or actors
                    event.summary.contains(entity_name) ||
                    event.actors.as_ref().map_or(false, |actors| {
                        actors.as_array().map_or(false, |arr| {
                            arr.iter().any(|actor| {
                                actor.as_object().map_or(false, |obj| {
                                    obj.get("context").and_then(|c| c.as_str())
                                        .map_or(false, |context| context.contains(entity_name))
                                })
                            })
                        })
                    })
                })
                .collect();
                
            if entity_events.is_empty() {
                return Ok(format!("No timeline information found for {}.", entity_name));
            }
            
            let mut narrative = format!("**{}'s Timeline:**\n\n", entity_name);
            narrative.push_str(&format!("**Recent Activity:** {} has been involved in {} events. ", 
                entity_name, entity_events.len()));
                
            narrative.push_str("Here are the most recent activities:\n\n");
            for (i, event) in entity_events.iter().take(5).enumerate() {
                let time_ago = self.format_relative_time(event.created_at);
                narrative.push_str(&format!("{}. **{}** - {} ({})\n", 
                    i + 1, event.event_type, event.summary, time_ago));
            }
            
            return Ok(narrative);
        }
        
        if entities.is_empty() {
            return Ok(format!("No timeline information found for {}.", entity_name));
        }

        let entity = &entities[0];
        let timeline_events = &entity.timeline_events;
        
        if timeline_events.is_empty() {
            return Ok(format!("{} has no recorded activity in the timeline.", entity_name));
        }

        let recent_events = timeline_events.iter()
            .take(5) // Most recent 5 events
            .collect::<Vec<_>>();

        let mut narrative = format!("**{}'s Timeline:**\n\n", entity_name);
        
        if let Some(current_state) = &entity.current_state {
            narrative.push_str(&format!("**Current Status:** {} is currently active with {} components tracked.\n\n", 
                entity_name, current_state.components.len()));
        }

        narrative.push_str(&format!("**Recent Activity:** {} has been involved in {} events. ", 
            entity_name, timeline_events.len()));

        if recent_events.len() > 0 {
            narrative.push_str("Here are the most recent activities:\n\n");
            for (i, event) in recent_events.iter().enumerate() {
                let time_ago = self.format_relative_time(event.event.created_at);
                narrative.push_str(&format!("{}. **{}** - {} ({})\n", 
                    i + 1, event.event.event_type, event.event.summary, time_ago));
            }
        }

        if !entity.relationships.is_empty() {
            narrative.push_str(&format!("\n**Relationships:** {} has {} active relationships affecting their current status.", 
                entity_name, entity.relationships.len()));
        }

        Ok(narrative)
    }

    /// Generate narrative for event participants queries (DEPRECATED: Now uses AI)
    #[allow(dead_code)]
    async fn generate_event_participants_narrative(
        &self,
        event_description: &str,
        entities: &[EntityTimelineContext],
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        if events.is_empty() {
            return Ok(format!("No events found matching '{}'.", event_description));
        }

        let mut narrative = format!("**Participants in '{}':**\n\n", event_description);
        
        if entities.is_empty() {
            narrative.push_str("No specific participants could be identified in these events.\n\n");
        } else {
            narrative.push_str(&format!("**Identified Participants:** {} entities were involved:\n\n", entities.len()));
            
            for (i, entity) in entities.iter().enumerate() {
                let name = entity.entity_name.as_ref().map(|s| s.as_str()).unwrap_or("Unknown Entity");
                let involvement = entity.timeline_events.len();
                narrative.push_str(&format!("{}. **{}** - Involved in {} related events", 
                    i + 1, name, involvement));
                
                if entity.relevance_score > 0.7 {
                    narrative.push_str(" (High relevance)");
                }
                narrative.push('\n');
            }
        }

        narrative.push_str(&format!("\n**Event Analysis:** {} events were analyzed for this query. ", events.len()));
        
        if events.len() > 1 {
            let time_span = self.calculate_event_time_span(events);
            narrative.push_str(&format!("These events span approximately {}.", time_span));
        }

        Ok(narrative)
    }

    /// Generate narrative for relationship history queries (DEPRECATED: Now uses AI)
    #[allow(dead_code)]
    async fn generate_relationship_history_narrative(
        &self,
        entity_a: &str,
        entity_b: &str,
        relationships: &[RelationshipAnalysis],
        _events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        if relationships.is_empty() {
            return Ok(format!("No relationship history found between {} and {}.", entity_a, entity_b));
        }

        let relationship = &relationships[0];
        let mut narrative = format!("**Relationship between {} and {}:**\n\n", entity_a, entity_b);

        // Current relationship status
        if let Some(current_rel) = &relationship.current_relationship {
            narrative.push_str(&format!("**Current Status:** {} and {} have a {} relationship.\n\n", 
                entity_a, entity_b, current_rel.relationship_type));
        } else {
            narrative.push_str(&format!("**Current Status:** No direct relationship currently exists between {} and {}.\n\n", 
                entity_a, entity_b));
        }

        // Relationship metrics
        let metrics = &relationship.analysis;
        narrative.push_str(&format!("**Relationship Metrics:**\n"));
        narrative.push_str(&format!("- **Strength:** {:.1}/10\n", metrics.strength * 10.0));
        narrative.push_str(&format!("- **Stability:** {:.1}/10\n", metrics.stability * 10.0));
        narrative.push_str(&format!("- **Trend:** {:?}\n", metrics.trend));
        narrative.push_str(&format!("- **Interactions:** {} recorded\n\n", metrics.interaction_count));

        // Historical evolution
        if !relationship.relationship_history.is_empty() {
            narrative.push_str(&format!("**Historical Evolution:** The relationship has evolved through {} key moments:\n\n", 
                relationship.relationship_history.len()));
            
            for (i, history_entry) in relationship.relationship_history.iter().take(3).enumerate() {
                let time_ago = self.format_relative_time(history_entry.timestamp);
                narrative.push_str(&format!("{}. **{}** - {} ({})\n", 
                    i + 1, history_entry.relationship_type, 
                    self.format_relationship_data(&history_entry.relationship_data), time_ago));
            }
        }

        Ok(narrative)
    }

    /// Generate narrative for location queries (DEPRECATED: Now uses AI)
    #[allow(dead_code)]
    async fn generate_location_query_narrative(
        &self,
        location_name: &str,
        entities: &[EntityTimelineContext],
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut narrative = format!("**Activity at {}:**\n\n", location_name);

        if entities.is_empty() {
            narrative.push_str(&format!("No entities are currently tracked at {}.\n\n", location_name));
        } else {
            narrative.push_str(&format!("**Current Occupants:** {} entities are present at {}:\n\n", 
                entities.len(), location_name));
            
            for (i, entity) in entities.iter().enumerate() {
                let name = entity.entity_name.as_ref().map(|s| s.as_str()).unwrap_or("Unknown Entity");
                narrative.push_str(&format!("{}. **{}**", i + 1, name));
                
                if let Some(current_state) = &entity.current_state {
                    if let Some(position) = current_state.components.get("position") {
                        narrative.push_str(&format!(" - {}", self.format_position_data(position)));
                    }
                }
                narrative.push('\n');
            }
        }

        if !events.is_empty() {
            narrative.push_str(&format!("\n**Recent Activity:** {} events have occurred at {} recently. ", 
                events.len(), location_name));
            
            let recent_events = events.iter().take(3).collect::<Vec<_>>();
            narrative.push_str("Most recent activities:\n\n");
            
            for (i, event) in recent_events.iter().enumerate() {
                let time_ago = self.format_relative_time(event.created_at);
                narrative.push_str(&format!("{}. **{}** - {} ({})\n", 
                    i + 1, event.event_type, event.summary, time_ago));
            }
        }

        Ok(narrative)
    }

    /// Generate narrative for general narrative queries (DEPRECATED: Now uses AI)
    #[allow(dead_code)]
    async fn generate_narrative_query_response(
        &self,
        query_text: &str,
        entities: &[EntityTimelineContext],
        events: &[ChronicleEvent],
        relationships: &[RelationshipAnalysis],
    ) -> Result<String, AppError> {
        let mut narrative = format!("**Query Results for: \"{}\"**\n\n", query_text);

        let total_data_points = entities.len() + events.len() + relationships.len();
        if total_data_points == 0 {
            return Ok("No relevant information found for your query.".to_string());
        }

        // Entities section
        if !entities.is_empty() {
            narrative.push_str(&format!("**Relevant Entities ({}):**\n", entities.len()));
            for (i, entity) in entities.iter().take(5).enumerate() {
                let name = entity.entity_name.as_ref().map(|s| s.as_str()).unwrap_or("Unknown Entity");
                narrative.push_str(&format!("{}. **{}** - Relevance: {:.1}/10\n", 
                    i + 1, name, entity.relevance_score * 10.0));
            }
            narrative.push('\n');
        }

        // Events section
        if !events.is_empty() {
            narrative.push_str(&format!("**Related Events ({}):**\n", events.len()));
            for (i, event) in events.iter().take(5).enumerate() {
                let time_ago = self.format_relative_time(event.created_at);
                narrative.push_str(&format!("{}. **{}** - {} ({})\n", 
                    i + 1, event.event_type, event.summary, time_ago));
            }
            narrative.push('\n');
        }

        // Relationships section
        if !relationships.is_empty() {
            narrative.push_str(&format!("**Relationship Insights ({}):**\n", relationships.len()));
            for (i, relationship) in relationships.iter().take(3).enumerate() {
                let strength = relationship.analysis.strength;
                let trend = &relationship.analysis.trend;
                narrative.push_str(&format!("{}. Relationship strength: {:.1}/10, Trend: {:?}\n", 
                    i + 1, strength * 10.0, trend));
            }
        }

        Ok(narrative)
    }

    /// Generate narrative for entity state at time queries (DEPRECATED: Now uses AI)
    #[allow(dead_code)]
    async fn generate_entity_state_narrative(
        &self,
        _entity_id: Uuid,
        timestamp: DateTime<Utc>,
        entities: &[EntityTimelineContext],
    ) -> Result<String, AppError> {
        let time_desc = self.format_relative_time(timestamp);
        let mut narrative = format!("**Entity State at {}:**\n\n", time_desc);

        if let Some(entity) = entities.first() {
            if let Some(state) = &entity.current_state {
                narrative.push_str(&format!("**Components ({}):**\n", state.components.len()));
                for (component_type, data) in &state.components {
                    narrative.push_str(&format!("- **{}:** {}\n", component_type, 
                        self.format_component_data(data)));
                }
            } else {
                narrative.push_str("No state information available for this entity at the specified time.\n");
            }
        } else {
            narrative.push_str("Entity not found or no data available at the specified time.\n");
        }

        Ok(narrative)
    }

    /// Generate narrative for causal chain queries
    async fn generate_causal_chain_narrative(
        &self,
        from_event: &Option<Uuid>,
        to_entity: &Option<Uuid>,
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut narrative = "**Causal Chain Analysis:**\n\n".to_string();

        if events.is_empty() {
            narrative.push_str("No causal relationships found in the event chain.\n");
            return Ok(narrative);
        }

        narrative.push_str(&format!("**Chain Length:** {} events in the causal sequence.\n\n", events.len()));

        narrative.push_str("**Causal Sequence:**\n");
        for (i, event) in events.iter().enumerate() {
            let time_ago = self.format_relative_time(event.created_at);
            narrative.push_str(&format!("{}. **{}** - {} ({})\n", 
                i + 1, event.event_type, event.summary, time_ago));
            
            if i < events.len() - 1 {
                narrative.push_str("   ↓ *caused by*\n");
            }
        }

        if let (Some(from_id), Some(to_id)) = (from_event, to_entity) {
            narrative.push_str(&format!("\n**Analysis:** Chain traces from event {} to entity {}.", 
                from_id, to_id));
        }

        Ok(narrative)
    }

    /// Generate narrative for temporal path queries
    async fn generate_temporal_path_narrative(
        &self,
        entity_id: Uuid,
        entities: &[EntityTimelineContext],
        _events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut narrative = format!("**Temporal Path for Entity {}:**\n\n", entity_id);

        if let Some(entity) = entities.first() {
            let timeline_events = &entity.timeline_events;
            
            if timeline_events.is_empty() {
                narrative.push_str("No temporal path data available for this entity.\n");
                return Ok(narrative);
            }

            narrative.push_str(&format!("**Path Length:** {} events tracked over time.\n\n", timeline_events.len()));
            
            narrative.push_str("**Temporal Sequence:**\n");
            for (i, event) in timeline_events.iter().enumerate() {
                let time_ago = self.format_relative_time(event.event.created_at);
                narrative.push_str(&format!("{}. **{}** - {} ({})\n", 
                    i + 1, event.event.event_type, event.event.summary, time_ago));
            }
        } else {
            narrative.push_str("Entity not found in the current context.\n");
        }

        Ok(narrative)
    }

    /// Generate narrative for relationship network queries
    async fn generate_relationship_network_narrative(
        &self,
        entity_id: Uuid,
        relationships: &[RelationshipAnalysis],
    ) -> Result<String, AppError> {
        let mut narrative = format!("**Relationship Network for Entity {}:**\n\n", entity_id);

        if relationships.is_empty() {
            narrative.push_str("No relationship network data available for this entity.\n");
            return Ok(narrative);
        }

        narrative.push_str(&format!("**Network Size:** {} relationships analyzed.\n\n", relationships.len()));

        narrative.push_str("**Network Analysis:**\n");
        for (i, relationship) in relationships.iter().enumerate() {
            let metrics = &relationship.analysis;
            narrative.push_str(&format!("{}. **Relationship {}:** Strength {:.1}/10, Trend {:?}\n", 
                i + 1, i + 1, metrics.strength * 10.0, metrics.trend));
        }

        Ok(narrative)
    }

    /// Generate narrative for causal influences queries
    async fn generate_causal_influences_narrative(
        &self,
        entity_id: Uuid,
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut narrative = format!("**Causal Influences on Entity {}:**\n\n", entity_id);

        if events.is_empty() {
            narrative.push_str("No causal influences found for this entity.\n");
            return Ok(narrative);
        }

        narrative.push_str(&format!("**Influence Analysis:** {} events have influenced this entity.\n\n", events.len()));

        narrative.push_str("**Key Influences:**\n");
        for (i, event) in events.iter().take(5).enumerate() {
            let time_ago = self.format_relative_time(event.created_at);
            narrative.push_str(&format!("{}. **{}** - {} ({})\n", 
                i + 1, event.event_type, event.summary, time_ago));
        }

        Ok(narrative)
    }

    /// Generate narrative for world model snapshot queries
    async fn generate_world_model_snapshot_narrative(
        &self,
        entities: &[EntityTimelineContext],
        events: &[ChronicleEvent],
        relationships: &[RelationshipAnalysis],
    ) -> Result<String, AppError> {
        let mut narrative = "**World Model Snapshot:**\n\n".to_string();

        let total_elements = entities.len() + events.len() + relationships.len();
        if total_elements == 0 {
            narrative.push_str("No world model data available for this snapshot.\n");
            return Ok(narrative);
        }

        narrative.push_str(&format!("**Snapshot Summary:** {} entities, {} events, {} relationships captured.\n\n", 
            entities.len(), events.len(), relationships.len()));

        if !entities.is_empty() {
            narrative.push_str(&format!("**Active Entities ({}):**\n", entities.len()));
            for (i, entity) in entities.iter().take(5).enumerate() {
                let name = entity.entity_name.as_ref().map(|s| s.as_str()).unwrap_or("Unknown Entity");
                narrative.push_str(&format!("{}. **{}**\n", i + 1, name));
            }
            narrative.push('\n');
        }

        if !events.is_empty() {
            narrative.push_str(&format!("**Recent Events ({}):**\n", events.len()));
            for (i, event) in events.iter().take(3).enumerate() {
                let time_ago = self.format_relative_time(event.created_at);
                narrative.push_str(&format!("{}. **{}** - {} ({})\n", 
                    i + 1, event.event_type, event.summary, time_ago));
            }
            narrative.push('\n');
        }

        if !relationships.is_empty() {
            narrative.push_str(&format!("**Relationship Overview ({}):**\n", relationships.len()));
            let avg_strength: f32 = relationships.iter()
                .map(|r| r.analysis.strength)
                .sum::<f32>() / relationships.len() as f32;
            narrative.push_str(&format!("- **Average Relationship Strength:** {:.1}/10\n", avg_strength * 10.0));
        }

        Ok(narrative)
    }
    
    // Item narrative generation methods
    
    /// Generate narrative for item timeline queries
    async fn generate_item_timeline_narrative(
        &self,
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut narrative = "**Item Ownership Timeline:**\n\n".to_string();
        
        if events.is_empty() {
            narrative.push_str("No item ownership history found.\n");
            return Ok(narrative);
        }
        
        let mut item_events: HashMap<String, Vec<(DateTime<Utc>, String, String)>> = HashMap::new();
        
        // Extract item events
        for event in events {
            if let Some(event_data) = &event.event_data {
                if let Some(items) = event_data.get("items").and_then(|i| i.as_array()) {
                    for item in items {
                        if let Some(item_obj) = item.as_object() {
                            let item_name = item_obj.get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("Unknown Item")
                                .to_string();
                            let action = item_obj.get("action")
                                .and_then(|a| a.as_str())
                                .unwrap_or("interacted with")
                                .to_string();
                            let description = self.format_item_event_description(item_obj, &action);
                            
                            item_events.entry(item_name)
                                .or_insert_with(Vec::new)
                                .push((event.timestamp_iso8601, action, description));
                        }
                    }
                }
            }
        }
        
        // Format timeline for each item
        for (item_name, mut events) in item_events {
            events.sort_by_key(|(timestamp, _, _)| *timestamp);
            narrative.push_str(&format!("**{}:**\n", item_name));
            
            for (timestamp, _action, description) in events {
                let time_str = timestamp.format("%Y-%m-%d %H:%M").to_string();
                narrative.push_str(&format!("- {} - {}\n", time_str, description));
            }
            narrative.push('\n');
        }
        
        Ok(narrative)
    }
    
    /// Generate narrative for item usage queries
    async fn generate_item_usage_narrative(
        &self,
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut narrative = "**Item Usage Patterns:**\n\n".to_string();
        
        if events.is_empty() {
            narrative.push_str("No item usage data found.\n");
            return Ok(narrative);
        }
        
        let mut usage_stats: HashMap<String, (usize, Vec<String>)> = HashMap::new();
        
        // Analyze usage patterns
        for event in events {
            if let Some(event_data) = &event.event_data {
                if let Some(items) = event_data.get("items").and_then(|i| i.as_array()) {
                    for item in items {
                        if let Some(item_obj) = item.as_object() {
                            if let Some(action) = item_obj.get("action").and_then(|a| a.as_str()) {
                                if action == "used" {
                                    let item_name = item_obj.get("name")
                                        .and_then(|n| n.as_str())
                                        .unwrap_or("Unknown Item")
                                        .to_string();
                                    let usage_type = item_obj.get("usage_type")
                                        .and_then(|u| u.as_str())
                                        .unwrap_or("generic")
                                        .to_string();
                                    
                                    let entry = usage_stats.entry(item_name).or_insert((0, Vec::new()));
                                    entry.0 += 1;
                                    if !entry.1.contains(&usage_type) {
                                        entry.1.push(usage_type);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Format usage statistics
        let mut sorted_items: Vec<_> = usage_stats.into_iter().collect();
        sorted_items.sort_by_key(|(_, (count, _))| std::cmp::Reverse(*count));
        
        for (item_name, (count, usage_types)) in sorted_items {
            narrative.push_str(&format!("**{}**: Used {} times\n", item_name, count));
            if !usage_types.is_empty() {
                narrative.push_str(&format!("  Usage types: {}\n", usage_types.join(", ")));
            }
            narrative.push('\n');
        }
        
        Ok(narrative)
    }
    
    /// Generate narrative for item location queries
    async fn generate_item_location_narrative(
        &self,
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut narrative = "**Item Location History:**\n\n".to_string();
        
        if events.is_empty() {
            narrative.push_str("No item location data found.\n");
            return Ok(narrative);
        }
        
        let mut location_history: HashMap<String, Vec<(DateTime<Utc>, String)>> = HashMap::new();
        
        // Track item movements
        for event in events {
            if let Some(event_data) = &event.event_data {
                if let Some(items) = event_data.get("items").and_then(|i| i.as_array()) {
                    for item in items {
                        if let Some(item_obj) = item.as_object() {
                            let item_name = item_obj.get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("Unknown Item")
                                .to_string();
                            let action = item_obj.get("action").and_then(|a| a.as_str()).unwrap_or("");
                            
                            let location_desc = match action {
                                "placed" => {
                                    item_obj.get("location")
                                        .and_then(|l| l.get("name").and_then(|n| n.as_str()).or_else(|| l.as_str()))
                                        .map(|loc| format!("Placed at {}", loc))
                                }
                                "moved" => {
                                    let from = item_obj.get("from_location")
                                        .and_then(|l| l.get("name").and_then(|n| n.as_str()).or_else(|| l.as_str()));
                                    let to = item_obj.get("to_location")
                                        .and_then(|l| l.get("name").and_then(|n| n.as_str()).or_else(|| l.as_str()));
                                    
                                    match (from, to) {
                                        (Some(f), Some(t)) => Some(format!("Moved from {} to {}", f, t)),
                                        (None, Some(t)) => Some(format!("Moved to {}", t)),
                                        (Some(f), None) => Some(format!("Moved from {}", f)),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            };
                            
                            if let Some(desc) = location_desc {
                                location_history.entry(item_name)
                                    .or_insert_with(Vec::new)
                                    .push((event.timestamp_iso8601, desc));
                            }
                        }
                    }
                }
            }
        }
        
        // Format location history
        for (item_name, mut locations) in location_history {
            locations.sort_by_key(|(timestamp, _)| *timestamp);
            narrative.push_str(&format!("**{}:**\n", item_name));
            
            for (timestamp, location) in locations {
                let time_str = timestamp.format("%Y-%m-%d %H:%M").to_string();
                narrative.push_str(&format!("- {} - {}\n", time_str, location));
            }
            narrative.push('\n');
        }
        
        Ok(narrative)
    }
    
    /// Generate narrative for item lifecycle queries
    async fn generate_item_lifecycle_narrative(
        &self,
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut narrative = "**Item Lifecycle Analysis:**\n\n".to_string();
        
        if events.is_empty() {
            narrative.push_str("No item lifecycle data found.\n");
            return Ok(narrative);
        }
        
        let mut lifecycles: HashMap<String, (Option<DateTime<Utc>>, Option<DateTime<Utc>>, String)> = HashMap::new();
        
        // Track item creation and destruction
        for event in events {
            if let Some(event_data) = &event.event_data {
                if let Some(items) = event_data.get("items").and_then(|i| i.as_array()) {
                    for item in items {
                        if let Some(item_obj) = item.as_object() {
                            let item_name = item_obj.get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("Unknown Item")
                                .to_string();
                            let action = item_obj.get("action").and_then(|a| a.as_str()).unwrap_or("");
                            
                            let entry = lifecycles.entry(item_name.clone()).or_insert((None, None, String::new()));
                            
                            match action {
                                "created" | "discovered" | "found" => {
                                    entry.0 = Some(event.timestamp_iso8601);
                                    entry.2 = format!("Created/Found: {}", action);
                                }
                                "destroyed" | "depleted" | "lost" => {
                                    entry.1 = Some(event.timestamp_iso8601);
                                    entry.2 = format!("{}, Status: {}", entry.2, action);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        
        // Format lifecycle information
        for (item_name, (created, destroyed, status)) in lifecycles {
            narrative.push_str(&format!("**{}:**\n", item_name));
            
            if let Some(created_time) = created {
                narrative.push_str(&format!("- Created: {}\n", created_time.format("%Y-%m-%d %H:%M")));
            }
            
            if let Some(destroyed_time) = destroyed {
                narrative.push_str(&format!("- Destroyed: {}\n", destroyed_time.format("%Y-%m-%d %H:%M")));
                
                if let Some(created_time) = created {
                    let duration = destroyed_time.signed_duration_since(created_time);
                    narrative.push_str(&format!("- Lifespan: {} days\n", duration.num_days()));
                }
            }
            
            if !status.is_empty() {
                narrative.push_str(&format!("- {}\n", status));
            }
            
            narrative.push('\n');
        }
        
        Ok(narrative)
    }
    
    /// Generate narrative for item interactions queries
    async fn generate_item_interactions_narrative(
        &self,
        entities: &[EntityTimelineContext],
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut narrative = "**Item Interaction Analysis:**\n\n".to_string();
        
        if events.is_empty() {
            narrative.push_str("No item interactions found.\n");
            return Ok(narrative);
        }
        
        // Count interactions by entity
        let mut interaction_counts: HashMap<String, HashMap<String, usize>> = HashMap::new();
        
        for entity in entities {
            for interaction in &entity.item_interactions {
                let entity_name = entity.entity_name.as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or("Unknown Entity");
                
                interaction_counts
                    .entry(entity_name.to_string())
                    .or_insert_with(HashMap::new)
                    .entry(interaction.item_name.clone())
                    .and_modify(|c| *c += 1)
                    .or_insert(1);
            }
        }
        
        // Format interaction summary
        for (entity_name, items) in interaction_counts {
            let total_interactions: usize = items.values().sum();
            narrative.push_str(&format!("**{}** ({} total interactions):\n", entity_name, total_interactions));
            
            let mut sorted_items: Vec<_> = items.into_iter().collect();
            sorted_items.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
            
            for (item_name, count) in sorted_items.into_iter().take(5) {
                narrative.push_str(&format!("- {}: {} interactions\n", item_name, count));
            }
            narrative.push('\n');
        }
        
        Ok(narrative)
    }
    
    /// Generate narrative for item search queries
    async fn generate_item_search_narrative(
        &self,
        events: &[ChronicleEvent],
    ) -> Result<String, AppError> {
        let mut narrative = "**Item Search Results:**\n\n".to_string();
        
        if events.is_empty() {
            narrative.push_str("No items found matching search criteria.\n");
            return Ok(narrative);
        }
        
        let mut found_items: HashMap<String, Vec<String>> = HashMap::new();
        
        // Collect unique items and their properties
        for event in events {
            if let Some(event_data) = &event.event_data {
                if let Some(items) = event_data.get("items").and_then(|i| i.as_array()) {
                    for item in items {
                        if let Some(item_obj) = item.as_object() {
                            let item_name = item_obj.get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("Unknown Item")
                                .to_string();
                            
                            let mut properties = Vec::new();
                            
                            if let Some(rarity) = item_obj.get("properties")
                                .and_then(|p| p.get("rarity"))
                                .and_then(|r| r.as_str()) {
                                properties.push(format!("Rarity: {}", rarity));
                            }
                            
                            if let Some(item_type) = item_obj.get("properties")
                                .and_then(|p| p.get("type"))
                                .and_then(|t| t.as_str()) {
                                properties.push(format!("Type: {}", item_type));
                            }
                            
                            if let Some(value) = item_obj.get("value")
                                .and_then(|v| v.as_i64()) {
                                properties.push(format!("Value: {}", value));
                            }
                            
                            found_items.entry(item_name)
                                .or_insert_with(Vec::new)
                                .extend(properties);
                        }
                    }
                }
            }
        }
        
        // Format search results
        narrative.push_str(&format!("Found {} unique items:\n\n", found_items.len()));
        
        for (item_name, properties) in found_items {
            narrative.push_str(&format!("**{}**\n", item_name));
            
            // Deduplicate properties
            let unique_props: std::collections::HashSet<_> = properties.into_iter().collect();
            for prop in unique_props {
                narrative.push_str(&format!("- {}\n", prop));
            }
            narrative.push('\n');
        }
        
        Ok(narrative)
    }
    
    /// Format item event description
    fn format_item_event_description(
        &self,
        item_obj: &serde_json::Map<String, JsonValue>,
        action: &str,
    ) -> String {
        match action {
            "discovered" | "found" => {
                if let Some(owner) = item_obj.get("owner").and_then(|o| o.as_str()) {
                    format!("Discovered by entity {}", owner)
                } else {
                    "Discovered".to_string()
                }
            }
            "created" => {
                if let Some(creator) = item_obj.get("creator").and_then(|c| c.as_str()) {
                    format!("Created by entity {}", creator)
                } else {
                    "Created".to_string()
                }
            }
            "transferred" => {
                let from = item_obj.get("from_owner").and_then(|f| f.as_str());
                let to = item_obj.get("to_owner").and_then(|t| t.as_str());
                match (from, to) {
                    (Some(f), Some(t)) => format!("Transferred from {} to {}", f, t),
                    _ => "Ownership transferred".to_string(),
                }
            }
            "used" => {
                let usage_type = item_obj.get("usage_type")
                    .and_then(|u| u.as_str())
                    .unwrap_or("generic");
                format!("Used ({})", usage_type)
            }
            "destroyed" => {
                if let Some(cause) = item_obj.get("destruction_cause").and_then(|c| c.as_str()) {
                    format!("Destroyed by {}", cause)
                } else {
                    "Destroyed".to_string()
                }
            }
            _ => format!("Action: {}", action),
        }
    }

    // Helper methods for formatting
    
    /// Format relative time from timestamp
    fn format_relative_time(&self, timestamp: DateTime<Utc>) -> String {
        let now = chrono::Utc::now();
        let duration = now.signed_duration_since(timestamp);
        
        if duration.num_days() > 0 {
            format!("{} days ago", duration.num_days())
        } else if duration.num_hours() > 0 {
            format!("{} hours ago", duration.num_hours())
        } else if duration.num_minutes() > 0 {
            format!("{} minutes ago", duration.num_minutes())
        } else {
            "Just now".to_string()
        }
    }

    /// Calculate time span between events
    fn calculate_event_time_span(&self, events: &[ChronicleEvent]) -> String {
        if events.len() < 2 {
            return "single event".to_string();
        }

        let earliest = events.iter().min_by_key(|e| e.created_at);
        let latest = events.iter().max_by_key(|e| e.created_at);
        
        if let (Some(earliest), Some(latest)) = (earliest, latest) {
            let duration = latest.created_at.signed_duration_since(earliest.created_at);
            if duration.num_days() > 0 {
                format!("{} days", duration.num_days())
            } else if duration.num_hours() > 0 {
                format!("{} hours", duration.num_hours())
            } else {
                format!("{} minutes", duration.num_minutes())
            }
        } else {
            "unknown timespan".to_string()
        }
    }

    /// Format relationship data for display
    fn format_relationship_data(&self, data: &serde_json::Value) -> String {
        if let Some(trust) = data.get("trust").and_then(|v| v.as_f64()) {
            format!("Trust: {:.1}/10", trust * 10.0)
        } else if let Some(strength) = data.get("strength").and_then(|v| v.as_f64()) {
            format!("Strength: {:.1}/10", strength * 10.0)
        } else {
            "Relationship data".to_string()
        }
    }

    /// Format position data for display
    fn format_position_data(&self, position: &serde_json::Value) -> String {
        if let Some(position_obj) = position.as_object() {
            if let (Some(x), Some(y)) = (
                position_obj.get("x").and_then(|v| v.as_f64()),
                position_obj.get("y").and_then(|v| v.as_f64())
            ) {
                format!("Position ({:.1}, {:.1})", x, y)
            } else {
                "Position data".to_string()
            }
        } else {
            "Position data".to_string()
        }
    }

    /// Format component data for display
    fn format_component_data(&self, data: &serde_json::Value) -> String {
        match data {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Object(obj) => {
                if obj.len() <= 3 {
                    // Show key-value pairs for small objects
                    obj.iter()
                        .map(|(k, v)| format!("{}: {}", k, v))
                        .collect::<Vec<_>>()
                        .join(", ")
                } else {
                    format!("Complex data ({} fields)", obj.len())
                }
            }
            serde_json::Value::Array(arr) => {
                format!("Array with {} items", arr.len())
            }
            serde_json::Value::Null => "No data".to_string(),
        }
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