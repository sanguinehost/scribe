# ECS Incremental Enhancement Implementation Plan

## Executive Summary

**Status: APPROVED FOR IMPLEMENTATION**

This document provides concrete implementation steps for enhancing the existing ECS with graph-like capabilities to support advanced LLM reasoning, based on the strategic pivot outlined in `contextual_query_planner.md`.

**Key Success Factors:**
- ✅ Preserves investment in robust existing system
- ✅ Delivers immediate value through incremental enhancements  
- ✅ Achieves 80% of TKG benefits with 20% of the effort
- ✅ Maintains performance on proven PostgreSQL/Redis stack
- ✅ Enables advanced LLM reasoning capabilities

**Critical Implementation Warnings Integrated:**
- ⚠️ **Data Consistency**: Use dynamic CausalComponent generation to maintain single source of truth
- ⚠️ **Scope Management**: Prioritize WorldModelSnapshot API; defer complex NLP to v1.1
- ⚠️ **Timeline Risk**: Focus on core reasoning capabilities over convenience features

## Overview

This plan represents the optimal engineering approach to deliver advanced reasoning capabilities while mitigating architectural and timeline risks. The incremental enhancement strategy maximizes immediate value and preserves future flexibility.

## Phase 1: Foundation Enhancements (Weeks 1-2)

### 1.1 Database Schema Updates

#### Task 1.1.1: Create migration for enhanced relationships
```sql
-- Migration: 2024_01_enhanced_ecs_relationships.sql

-- Add graph-like metadata to relationships
ALTER TABLE ecs_entity_relationships 
ADD COLUMN relationship_category VARCHAR(50) DEFAULT 'social',
ADD COLUMN strength FLOAT DEFAULT 0.5 CHECK (strength >= 0.0 AND strength <= 1.0),
ADD COLUMN causal_metadata JSONB DEFAULT '{}',
ADD COLUMN temporal_validity JSONB DEFAULT '{}';

-- Add indexes for efficient graph queries
CREATE INDEX idx_ecs_relationships_category ON ecs_entity_relationships(relationship_category);
CREATE INDEX idx_ecs_relationships_strength ON ecs_entity_relationships(strength);
CREATE INDEX idx_ecs_relationships_temporal ON ecs_entity_relationships USING GIN(temporal_validity);

-- Add causal tracking to chronicle events
ALTER TABLE chronicle_events
ADD COLUMN caused_by_event_id UUID REFERENCES chronicle_events(id),
ADD COLUMN causes_event_ids UUID[] DEFAULT '{}';

CREATE INDEX idx_chronicle_causal_chain ON chronicle_events(caused_by_event_id);
```

#### Task 1.1.2: Update Diesel schema
```rust
// Update schema.rs after running diesel migration

table! {
    ecs_entity_relationships (id) {
        id -> Uuid,
        from_entity_id -> Uuid,
        to_entity_id -> Uuid,
        relationship_type -> Text,
        relationship_data -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        user_id -> Uuid,
        // New fields
        relationship_category -> Nullable<Varchar>,
        strength -> Nullable<Float>,
        causal_metadata -> Nullable<Jsonb>,
        temporal_validity -> Nullable<Jsonb>,
    }
}
```

### 1.2 Model Extensions

#### Task 1.2.1: Create CausalComponent (Dynamic Generation Pattern)

**⚠️ WARNING: Single Source of Truth**
To avoid data consistency issues, we implement `CausalComponent` as a **dynamically generated struct** assembled at query time from underlying relationship and event data, rather than a separately persisted component.

```rust
// backend/src/models/ecs.rs - Add to existing file

/// Tracks causal relationships for entities (Generated dynamically, not persisted)
/// 
/// This component is assembled at query time from:
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
    pub async fn generate_for_entity(
        entity_id: Uuid,
        user_id: Uuid,
        db_pool: &PgPool,
    ) -> Result<Self, AppError> {
        // Query causal relationships
        let causal_relationships = Self::get_causal_relationships(entity_id, user_id, db_pool).await?;
        
        // Query causal event chains
        let event_chains = Self::get_event_chains(entity_id, user_id, db_pool).await?;
        
        // Assemble component
        Ok(Self {
            caused_by_events: event_chains.caused_by,
            causes_events: event_chains.causes,
            causal_confidence: Self::calculate_confidence(&causal_relationships),
            causal_chain_depth: event_chains.max_depth,
            causal_metadata: Self::build_metadata(&causal_relationships, &event_chains),
        })
    }
    
    /// Component type identifier (for compatibility with Component trait)
    pub fn component_type() -> &'static str {
        "Causal"
    }
}

/// Enhanced relationship categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RelationshipCategory {
    Social,      // Character relationships
    Spatial,     // Location-based relationships
    Causal,      // Cause-effect relationships
    Ownership,   // Possession relationships
    Temporal,    // Time-based relationships
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemporalValidity {
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CausalMetadata {
    pub caused_by_event: Uuid,
    pub confidence: f32,
    pub causality_type: String, // direct, indirect, probabilistic
}
```

### 1.3 Update ChronicleEcsTranslator

#### Task 1.3.1: Add causal tracking
```rust
// backend/src/services/chronicle_ecs_translator.rs - Enhance existing translate_event method

impl ChronicleEcsTranslator {
    /// Enhanced translation with causal tracking
    pub async fn translate_event_with_causality(
        &self, 
        event: &ChronicleEvent, 
        user_id: Uuid,
        previous_event: Option<&ChronicleEvent>,
    ) -> Result<TranslationResult, AppError> {
        let mut result = self.translate_event(event, user_id).await?;
        
        // Track causality if there's a previous event
        if let Some(prev) = previous_event {
            // Add causal component to affected entities
            for actor in event.get_actors()? {
                result.component_updates.push(ComponentUpdate {
                    entity_id: actor.entity_id,
                    component_type: "Causal".to_string(),
                    component_data: json!({
                        "operation": "add_cause",
                        "caused_by_event": prev.id,
                        "confidence": 0.8,
                    }),
                    operation: ComponentOperation::Update,
                });
            }
            
            // Update chronicle event causality
            self.update_event_causality(event.id, prev.id).await?;
        }
        
        Ok(result)
    }
    
    /// Create causal relationships between entities
    fn create_causal_relationships(
        &self,
        event: &ChronicleEvent,
        actors: &[EventActor],
        result: &mut TranslationResult,
    ) -> Result<(), AppError> {
        // Agent causes effect on Patient
        let agents: Vec<_> = actors.iter().filter(|a| a.role == ActorRole::Agent).collect();
        let patients: Vec<_> = actors.iter().filter(|a| a.role == ActorRole::Patient).collect();
        
        for agent in &agents {
            for patient in &patients {
                result.relationship_updates.push(RelationshipUpdate {
                    from_entity_id: agent.entity_id,
                    to_entity_id: patient.entity_id,
                    relationship_type: "causes_effect_on".to_string(),
                    relationship_data: json!({
                        "category": "causal",
                        "strength": 0.7,
                        "caused_by_event": event.id,
                        "timestamp": event.created_at,
                    }),
                    operation: RelationshipOperation::Create,
                });
            }
        }
        
        Ok(())
    }
}
```

## Phase 2: Query Engine Enhancement (Weeks 3-5)

### 2.1 World Model Snapshot API

#### Task 2.1.1: Create world model types
```rust
// backend/src/models/world_model.rs - New file

use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use serde_json::Value as JsonValue;

/// Complete snapshot of the world state at a point in time
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySnapshot {
    pub entity_id: Uuid,
    pub archetype: String,
    pub name: Option<String>,
    pub components: HashMap<String, JsonValue>,
    pub last_modified: DateTime<Utc>,
    pub causal_influences: Vec<Uuid>, // Recent events that affected this entity
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipSnapshot {
    pub from_entity: Uuid,
    pub to_entity: Uuid,
    pub relationship_type: String,
    pub category: String,
    pub strength: f32,
    pub metadata: JsonValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalEventSnapshot {
    pub event_id: Uuid,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub affected_entities: Vec<Uuid>,
    pub caused_by: Option<Uuid>,
    pub causes: Vec<Uuid>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialHierarchy {
    pub root_locations: Vec<Uuid>,
    pub containment_tree: HashMap<Uuid, Vec<Uuid>>,
    pub entity_locations: HashMap<Uuid, Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalContext {
    pub current_time: DateTime<Utc>,
    pub time_window: Duration,
    pub significant_moments: Vec<DateTime<Utc>>,
}

/// LLM-optimized world context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMWorldContext {
    pub entity_summaries: Vec<EntitySummary>,
    pub relationship_graph: RelationshipGraph,
    pub causal_chains: Vec<CausalChain>,
    pub spatial_context: SpatialContext,
    pub recent_changes: Vec<RecentChange>,
    pub reasoning_hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitySummary {
    pub entity_id: Uuid,
    pub name: String,
    pub entity_type: String,
    pub current_state: String,
    pub key_attributes: HashMap<String, String>,
    pub recent_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub clusters: Vec<RelationshipCluster>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalChain {
    pub chain_id: Uuid,
    pub root_cause: String,
    pub steps: Vec<CausalStep>,
    pub final_effect: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalStep {
    pub event: String,
    pub entities_involved: Vec<String>,
    pub timestamp: DateTime<Utc>,
    pub confidence: f32,
}
```

### 2.2 Enhanced Query Types

#### Task 2.2.1: Extend HybridQueryService
```rust
// backend/src/services/hybrid_query_service.rs - Add to existing types

/// Enhanced query types for graph-like operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnhancedHybridQueryType {
    /// All existing HybridQueryType variants...
    
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
        categories: Option<Vec<RelationshipCategory>>,
    },
    
    /// Find causal influences on entity
    CausalInfluences {
        entity_id: Uuid,
        time_window: Duration,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpatialScope {
    pub root_location: Uuid,
    pub max_depth: u32,
    pub include_adjacent: bool,
}
```

#### Task 2.2.2: Implement world model generation
```rust
// backend/src/services/world_model_service.rs - New file

use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use tracing::{info, debug, instrument};

use crate::{
    PgPool,
    errors::AppError,
    models::world_model::*,
    services::{
        ecs_entity_manager::EcsEntityManager,
        hybrid_query_service::HybridQueryService,
        chronicle_service::ChronicleService,
    },
};

pub struct WorldModelService {
    db_pool: Arc<PgPool>,
    entity_manager: Arc<EcsEntityManager>,
    query_service: Arc<HybridQueryService>,
    chronicle_service: Arc<ChronicleService>,
}

impl WorldModelService {
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn generate_world_snapshot(
        &self,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        timestamp: Option<DateTime<Utc>>,
        options: WorldModelOptions,
    ) -> Result<WorldModelSnapshot, AppError> {
        let snapshot_time = timestamp.unwrap_or_else(Utc::now);
        
        // Step 1: Get all entities (or focused subset)
        let entities = self.gather_entities(user_id, &options).await?;
        
        // Step 2: Get active relationships
        let relationships = self.gather_relationships(user_id, &entities).await?;
        
        // Step 3: Get recent causal events
        let recent_events = self.gather_recent_events(
            user_id, 
            chronicle_id, 
            snapshot_time, 
            options.time_window
        ).await?;
        
        // Step 4: Build spatial hierarchy
        let spatial_hierarchy = self.build_spatial_hierarchy(user_id, &entities).await?;
        
        // Step 5: Create temporal context
        let temporal_context = TemporalContext {
            current_time: snapshot_time,
            time_window: options.time_window,
            significant_moments: self.identify_significant_moments(&recent_events),
        };
        
        Ok(WorldModelSnapshot {
            snapshot_id: Uuid::new_v4(),
            user_id,
            chronicle_id,
            timestamp: snapshot_time,
            entities,
            active_relationships: relationships,
            recent_events,
            spatial_hierarchy,
            temporal_context,
        })
    }
    
    /// Convert world snapshot to LLM-optimized format
    pub fn snapshot_to_llm_context(
        &self,
        snapshot: &WorldModelSnapshot,
        focus: LLMContextFocus,
    ) -> Result<LLMWorldContext, AppError> {
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
}

#[derive(Debug, Clone)]
pub struct WorldModelOptions {
    pub time_window: Duration,
    pub focus_entities: Option<Vec<Uuid>>,
    pub include_inactive: bool,
    pub max_entities: usize,
}

#[derive(Debug, Clone)]
pub struct LLMContextFocus {
    pub query_intent: String,
    pub key_entities: Vec<Uuid>,
    pub time_focus: TimeFocus,
    pub reasoning_depth: ReasoningDepth,
}

#[derive(Debug, Clone)]
pub enum TimeFocus {
    Current,
    Historical(Duration),
    Specific(DateTime<Utc>),
}

#[derive(Debug, Clone)]
pub enum ReasoningDepth {
    Surface,  // Just facts
    Causal,   // Include causality
    Deep,     // Full reasoning chains
}
```

## Phase 3: LLM Integration Layer (Weeks 6-7)

**⚠️ SCOPE WARNING: Natural Language Interface Complexity**
The `natural_language_query` function represents building an "LLM-as-a-query-planner" which is a significant feature in its own right. To de-risk the timeline, we prioritize the **WorldModelSnapshot API** as the primary deliverable, with full natural language interface as a fast-follow "v1.1" feature.

**Phase 3 Priority Order:**
1. **PRIMARY**: `WorldModelSnapshot` API and LLM context generation
2. **SECONDARY**: Basic query intent detection  
3. **V1.1 FEATURE**: Full natural language query processing

### 3.1 World Model API (Primary Deliverable)

#### Task 3.1.1: Complete WorldModelSnapshot implementation (PRIORITY 1)

Focus on delivering the core reasoning API first, ensuring the LLM has access to structured world context.

#### Task 3.1.2: Basic NLP query handler (PRIORITY 2)
```rust
// backend/src/services/nlp_query_handler.rs - New file

use std::sync::Arc;
use uuid::Uuid;
use chrono::Duration;
use tracing::{info, instrument};

use crate::{
    errors::AppError,
    models::world_model::*,
    services::{
        world_model_service::{WorldModelService, LLMContextFocus, TimeFocus, ReasoningDepth},
        hybrid_query_service::{HybridQueryService, EnhancedHybridQueryType},
    },
};

pub struct NLPQueryHandler {
    world_model_service: Arc<WorldModelService>,
    query_service: Arc<HybridQueryService>,
}

impl NLPQueryHandler {
    /// Process natural language query and return LLM-ready response
    #[instrument(skip(self), fields(user_id = %user_id))]
    pub async fn process_natural_language_query(
        &self,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        query: &str,
        context_window: Duration,
    ) -> Result<LLMReasoningResponse, AppError> {
        info!("Processing natural language query: {}", query);
        
        // Step 1: Analyze query intent
        let intent = self.analyze_query_intent(query)?;
        
        // Step 2: Generate world model snapshot
        let snapshot = self.world_model_service.generate_world_snapshot(
            user_id,
            chronicle_id,
            None, // Current time
            WorldModelOptions {
                time_window: context_window,
                focus_entities: intent.focus_entities.clone(),
                include_inactive: false,
                max_entities: 100,
            },
        ).await?;
        
        // Step 3: Convert to LLM context
        let llm_context = self.world_model_service.snapshot_to_llm_context(
            &snapshot,
            LLMContextFocus {
                query_intent: intent.intent_type.to_string(),
                key_entities: intent.focus_entities.unwrap_or_default(),
                time_focus: intent.time_focus,
                reasoning_depth: intent.reasoning_depth,
            },
        )?;
        
        // Step 4: Execute specific queries based on intent
        let query_results = self.execute_intent_queries(&intent, user_id).await?;
        
        // Step 5: Generate reasoning suggestions
        let reasoning_suggestions = self.generate_reasoning_suggestions(&intent, &llm_context)?;
        
        // Step 6: Format response
        Ok(LLMReasoningResponse {
            original_query: query.to_string(),
            interpreted_intent: intent,
            world_context: llm_context,
            specific_results: query_results,
            reasoning_suggestions,
            confidence: 0.85,
        })
    }
    
    fn analyze_query_intent(&self, query: &str) -> Result<QueryIntent, AppError> {
        // Simple keyword-based intent detection (could be enhanced with NLP)
        let query_lower = query.to_lowercase();
        
        let intent_type = if query_lower.contains("what caused") || query_lower.contains("why did") {
            IntentType::CausalReasoning
        } else if query_lower.contains("where is") || query_lower.contains("located at") {
            IntentType::SpatialQuery
        } else if query_lower.contains("relationship") || query_lower.contains("between") {
            IntentType::RelationshipAnalysis
        } else if query_lower.contains("what happened") || query_lower.contains("timeline") {
            IntentType::TemporalQuery
        } else {
            IntentType::GeneralInquiry
        };
        
        Ok(QueryIntent {
            intent_type,
            focus_entities: None, // Would extract entity names/IDs
            time_focus: TimeFocus::Current,
            reasoning_depth: ReasoningDepth::Causal,
            confidence: 0.7,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMReasoningResponse {
    pub original_query: String,
    pub interpreted_intent: QueryIntent,
    pub world_context: LLMWorldContext,
    pub specific_results: Vec<QueryResult>,
    pub reasoning_suggestions: Vec<ReasoningSuggestion>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryIntent {
    pub intent_type: IntentType,
    pub focus_entities: Option<Vec<Uuid>>,
    pub time_focus: TimeFocus,
    pub reasoning_depth: ReasoningDepth,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntentType {
    CausalReasoning,
    SpatialQuery,
    RelationshipAnalysis,
    TemporalQuery,
    GeneralInquiry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub result_type: String,
    pub data: JsonValue,
    pub relevance: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningSuggestion {
    pub suggestion: String,
    pub reasoning_path: Vec<String>,
    pub confidence: f32,
}
```

### 3.2 Prompt Engineering Framework

#### Task 3.2.1: Create prompt templates
```rust
// backend/src/services/prompt_templates.rs - New file

use crate::models::world_model::*;

pub struct PromptTemplates;

impl PromptTemplates {
    pub fn causal_reasoning_prompt(context: &LLMWorldContext, query: &str) -> String {
        format!(
            r#"You are analyzing a narrative world with the following context:

## Current World State
{}

## Causal Chains Identified
{}

## Your Task
Answer the following question using causal reasoning: "{}"

## Reasoning Guidelines
1. Trace through the causal chains to identify root causes
2. Consider both direct and indirect effects
3. Note any uncertainty in the causal relationships
4. Reference specific events and entities by name

## Response Format
Provide a clear narrative explanation that:
- Identifies the primary cause(s)
- Explains the causal chain step by step
- Notes any alternative explanations
- Assesses confidence in the conclusion
"#,
            Self::format_entity_summaries(&context.entity_summaries),
            Self::format_causal_chains(&context.causal_chains),
            query
        )
    }
    
    pub fn relationship_analysis_prompt(context: &LLMWorldContext, query: &str) -> String {
        format!(
            r#"You are analyzing relationships in a narrative world:

## Relationship Network
{}

## Recent Relationship Changes
{}

## Your Task
Answer: "{}"

## Analysis Framework
1. Identify key relationships relevant to the query
2. Analyze relationship strength and type
3. Consider how recent events affected relationships
4. Note any relationship patterns or clusters

## Response Format
Provide an analysis that includes:
- Current relationship status
- Historical context
- Key events that shaped the relationship
- Future implications
"#,
            Self::format_relationship_graph(&context.relationship_graph),
            Self::format_recent_changes(&context.recent_changes),
            query
        )
    }
    
    // Helper formatting methods
    fn format_entity_summaries(summaries: &[EntitySummary]) -> String {
        summaries.iter()
            .map(|s| format!("- {}: {} ({})", s.name, s.current_state, s.entity_type))
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    fn format_causal_chains(chains: &[CausalChain]) -> String {
        chains.iter()
            .map(|c| {
                format!("Chain: {} -> {} (confidence: {:.1})",
                    c.root_cause,
                    c.final_effect,
                    c.confidence
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}
```

## Implementation Timeline (Revised with Warnings Integrated)

| Week | Phase | Key Deliverables | Risk Mitigation |
|------|-------|------------------|-----------------|
| 1-2  | Foundation | Enhanced DB schema, model extensions, **dynamic causal tracking** | ⚠️ Use dynamic CausalComponent generation |
| 3-4  | Query Engine Part 1 | **World model API (PRIORITY)**, causal queries | Focus on core reasoning API first |
| 5    | Query Engine Part 2 | Temporal queries, relationship networks | Test against performance targets |
| 6    | LLM Integration Part 1 | **WorldModelSnapshot API (PRIMARY)**, basic intent detection | ⚠️ Defer complex NLP to v1.1 |
| 7    | LLM Integration Part 2 | Prompt templates, **basic** reasoning suggestions | Keep scope minimal for timeline |
| 8    | Testing & Optimization | Performance tuning, integration tests | Validate against success criteria |

**Deferred to v1.1:**
- Full natural language query processing
- Advanced intent recognition
- Complex reasoning chain generation

## Success Criteria

1. **Functionality**
   - [ ] Causal chains traceable through events
   - [ ] Temporal entity states reconstructable
   - [ ] Relationship networks queryable at any depth
   - [ ] World model snapshots generated < 500ms
   - [ ] Natural language queries processed successfully

2. **Performance**
   - [ ] No regression in existing query performance
   - [ ] Graph-like queries complete < 300ms
   - [ ] LLM context generation < 200ms
   - [ ] Cache hit rates maintained > 85%

3. **LLM Integration**
   - [ ] Structured context includes causal reasoning
   - [ ] Relationship graphs properly formatted
   - [ ] Reasoning hints relevant and helpful
   - [ ] Token-efficient representations

## Risk Mitigation (Enhanced with Expert Warnings)

1. **Data Consistency Risks (CRITICAL)**
   - **⚠️ Single Source of Truth**: Use dynamic CausalComponent generation to avoid storing causal links in multiple places
   - Use transactions for all updates
   - Validate causal chains against source data
   - Regular consistency checks between relationships and events
   - Audit trail for all changes

2. **Scope Creep Risks (NEW)**
   - **⚠️ NLP Complexity**: Treat natural language interface as separate v1.1 feature
   - Focus on WorldModelSnapshot API as primary Phase 3 deliverable
   - Resist temptation to over-engineer initial version
   - Maintain clear feature boundaries

3. **Performance Risks**
   - Monitor query performance continuously
   - Add indexes proactively for graph-like queries
   - Cache aggressively, especially for world snapshots
   - Fallback to simpler queries if complex ones timeout

4. **Timeline Risks**
   - Prioritize core reasoning API over convenience features
   - Weekly checkpoint reviews against deliverables
   - Early performance testing to catch issues
   - Clear definition of MVP vs nice-to-have

5. **Technical Complexity Risks**
   - Implement incrementally with rollback capability
   - Test each enhancement thoroughly before proceeding
   - Maintain backwards compatibility at all times
   - Document architectural decisions and trade-offs