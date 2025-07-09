# Sanguine Scribe: Living World Architecture

**Version:** 2.0 (Current Implementation)  
**Last Updated:** 2025-01-09  
**Status:** Production Ready with Critical Gaps Identified

## Executive Summary

Sanguine Scribe is architected as a **living world substrate** - a foundation for persistent, intelligent narrative ecosystems where characters truly live between sessions, worlds remember and evolve, and every action ripples through time with realistic consequences.

**Current State:** 60-70% architecturally complete with sophisticated foundation systems but critical gaps preventing full "living world" functionality.

**Vision:** Transform from "sophisticated chatbot" to "digital consciousness substrate" - the foundation for AI beings that can truly live, grow, and evolve in persistent narrative worlds.

## Core Architecture: The Living World Stack

### 1. Narrative Memory Layer (✅ Complete)
**Chronicle System**: Persistent cross-session narrative memory
- **Event Ontology**: Structured event taxonomy with hierarchical classification
- **Causal Tracking**: Events linked through causality chains
- **Temporal Persistence**: Events maintain chronological order across sessions
- **Contextual Embedding**: RAG-powered semantic search across all narrative history

```rust
// Example: Chronicle event with causal tracking
ChronicleEvent {
    id: uuid,
    event_type: "CHARACTER.STATE_CHANGE.DEATH",
    caused_by_event_id: Some(previous_combat_event_id),
    causes_event_ids: vec![funeral_event_id, inheritance_event_id],
    actors: vec![
        EventActor { entity_id: character_uuid, role: Agent },
        EventActor { entity_id: weapon_uuid, role: Instrument }
    ],
    valence: vec![
        EventValence { target: ally_uuid, valence_type: Grief, change: -0.8 }
    ]
}
```

### 2. Entity-Component System (⚠️ Partial - Critical Gaps)
**World State Management**: Structured entity relationships and components
- **Entity Identity**: Persistent UUID-based entity tracking
- **Component Architecture**: Modular entity properties (Health, Position, Relationships, etc.)
- **Spatial Hierarchy**: Containment relationships and spatial queries
- **Temporal Validity**: Time-aware component states

```rust
// Example: Rich entity with spatial and temporal components
Entity {
    id: character_uuid,
    archetype_signature: "Name|Position|Health|Relationships|Inventory",
    components: vec![
        NameComponent { name: "Elara", aliases: vec!["the healer", "sister"] },
        PositionComponent { zone: "tavern_interior", contained_by: Some(tavern_uuid) },
        HealthComponent { current: 85, max: 100, injuries: vec!["arrow wound"] },
        RelationshipsComponent { relationships: vec![
            Relationship { target: player_uuid, trust: 0.8, relationship_type: "ally" }
        ]}
    ]
}
```

### 3. Agentic AI Framework (✅ Complete)
**Autonomous Narrative Intelligence**: AI agents with tool access
- **4-Step Workflow**: Triage → Retrieve → Plan → Execute
- **Tool Architecture**: "Everything as a Tool" design pattern
- **Multi-Model Support**: Gemini 2.5 Pro/Flash with extensible framework
- **Context-Aware**: Deep integration with chronicle and ECS systems

```rust
// Example: Agentic workflow processing narrative events
NarrativeWorkflow {
    step_1: analyze_text_significance(messages) -> is_significant: true,
    step_2: search_knowledge_base(query: "Elara combat") -> existing_context,
    step_3: plan_actions(context, events) -> vec![create_chronicle_event, update_health],
    step_4: execute_tools(plan) -> world_state_updated
}
```

### 4. Advanced RAG System (✅ Complete)
**Semantic Memory and Context Retrieval**
- **Multi-Stage Retrieval**: Semantic search → Re-ranking → Diversification
- **Hybrid Search**: Vector similarity + keyword matching + causal relationships
- **Context Windowing**: Intelligent chunking with overflow handling
- **Privacy-Aware**: End-to-end encryption with semantic search

### 5. Encryption & Privacy Layer (✅ Complete)
**Zero-Knowledge Architecture**
- **End-to-End Encryption**: Client-side key derivation, server-side encrypted storage
- **Searchable Encryption**: Semantic search on encrypted content
- **Session DEK Management**: Secure key handling for AI processing
- **GDPR Compliance**: User-controlled data with privacy-preserving analytics

## Critical Gaps: The "Living World" Blockers

### 1. 🔴 Entity Resolution is Fundamentally Broken
**Problem**: AI constantly fails to match narrative entities to existing ones
- "Entity compatibility validation failed: Name mismatch: existing 'weequays_comm_unit' vs new 'swiftwind_ship_id'"
- Characters, locations, items exist in isolation bubbles
- No persistent identity across mentions

**Impact**: 
- Grakol exists, The Wayward Beacon exists, but no connection that Grakol runs a cantina inside The Wayward Beacon
- "The tall dark stranger" from Chapter 1 isn't recognized as "Vader" in Chapter 5
- Entity explosion instead of persistent identity

### 2. 🔴 Component Data is Effectively Useless
**Problem**: Most entity components are empty shells
- Position components: `{}`
- Health components: `null` or empty
- Relationships: `{"relationships": []}`
- No spatial containment (characters inside locations)

**Impact**: 
- Can't answer "Who is currently in the tavern?"
- No inventory tracking ("What items does the player have?")
- No relationship context ("Who trusts whom?")

### 3. 🔴 No Spatial or Relational Context
**Problem**: Entities exist in a void
- No "inside/outside" relationships
- No "character X is in location Y" tracking
- No "item Z belongs to character A" ownership

**Impact**: 
- No spatial hierarchy (planets → cities → buildings → rooms → characters/items)
- Can't query "Find all entities of type X within spatial distance Y"
- No containment relationships

### 4. 🔴 Chronicle Events Don't Drive World State
**Problem**: Events happen and disappear into the void
- "Character X picks up sword Y" doesn't update X's inventory component
- Combat events don't affect health components
- Relationship changes don't persist in relationship components

**Impact**: 
- World doesn't remember state changes
- Characters can die in one scene and be alive in the next
- No persistent consequences

### 5. 🔴 AI Prompts Are Shallow and Context-Blind
**Problem**: Entity resolution tool gets minimal context
- Trying to resolve "Grakol" without understanding "Grakol is a Rodian cantina owner"
- No rich contextual prompts with world state
- Generic, bland entity creation

**Impact**: 
- Even when AI creates entities, they're context-less
- No rich component extraction from narrative
- Poor entity matching decisions

## The Living World Requirements

### 1. Persistent Identity Management
- Characters maintain consistent identity across sessions
- Aliases and nicknames properly linked ("The Dark Lord" = "Vader" = "Anakin")
- Physical descriptions, personality traits, relationships persist
- Items and locations maintain properties and contents

### 2. Spatial and Temporal Coherence
- Characters exist in specific locations at specific times
- Travel between locations takes time and has consequences
- Items exist in inventory, locations, or containers
- Weather, lighting, environmental conditions affect gameplay

### 3. Dynamic Relationship Networks
- Trust, fear, love, hatred evolve based on interactions
- Reputation systems track character standing with factions
- Social hierarchies and power structures emerge organically
- Information spreads through believable social networks

### 4. Consequence-Driven Narrative
- Actions have logical, persistent consequences
- Character deaths, injuries, transformations are remembered
- Economic systems track wealth, resources, trade
- Political changes affect the broader world state

### 5. Emergent Complexity
- Simple rules create complex behaviors
- Characters can take autonomous actions between sessions
- World events can trigger without player involvement
- NPCs pursue their own goals and react to world changes

## Implementation Architecture

### Current Tech Stack
```
Frontend: SvelteKit + TypeScript + TailwindCSS
Backend: Rust + Axum + Diesel ORM
Database: PostgreSQL + Qdrant Vector DB
AI: Google Gemini 2.5 Pro/Flash
Cache: Redis
Encryption: ChaCha20-Poly1305 + Argon2
```

### Core Services
```rust
// Main application services
pub struct AppState {
    pub ai_client: Arc<dyn AiClient>,
    pub chronicle_service: Arc<ChronicleService>,
    pub lorebook_service: Arc<LorebookService>,
    pub ecs_entity_manager: Arc<EcsEntityManager>,
    pub narrative_intelligence_service: Arc<NarrativeIntelligenceService>,
    pub embedding_pipeline_service: Arc<EmbeddingPipelineService>,
    pub chronicle_ecs_translator: Arc<ChronicleEcsTranslator>,
    // ... other services
}
```

### Database Schema (ECS Layer)
```sql
-- Core ECS tables
CREATE TABLE ecs_entities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    archetype_signature TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE ecs_components (
    id UUID PRIMARY KEY,
    entity_id UUID NOT NULL REFERENCES ecs_entities(id),
    user_id UUID NOT NULL,
    component_type TEXT NOT NULL,
    component_data JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(entity_id, component_type)
);

CREATE TABLE ecs_entity_relationships (
    id UUID PRIMARY KEY,
    from_entity_id UUID NOT NULL REFERENCES ecs_entities(id),
    to_entity_id UUID NOT NULL REFERENCES ecs_entities(id),
    user_id UUID NOT NULL,
    relationship_type TEXT NOT NULL,
    relationship_data JSONB NOT NULL,
    relationship_category TEXT, -- Enhanced: 'social', 'spatial', 'causal', etc.
    strength DOUBLE PRECISION,   -- Enhanced: 0.0-1.0
    causal_metadata JSONB,       -- Enhanced: causality tracking
    temporal_validity JSONB,     -- Enhanced: time-bound relationships
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

## Next Steps: Completing the Living World

### Phase 1: Entity Resolution Revolution
1. **Enhanced Context-Aware Resolution**: Deep contextual understanding with semantic similarity
2. **Persistent Identity Tracking**: Perfect entity matching across all mentions
3. **Rich Component Extraction**: Extract detailed world state from narrative

### Phase 2: Component Enrichment Pipeline
1. **Spatial World Model**: Full containment hierarchy and spatial relationships
2. **Rich Component Data**: Meaningful health, inventory, relationship tracking
3. **Temporal State Management**: Time-aware component evolution

### Phase 3: Consequence Engine
1. **Event-Driven State Updates**: Chronicle events automatically update ECS components
2. **Causal Relationship Tracking**: Actions have persistent, logical consequences
3. **World State Persistence**: Changes persist across sessions

### Phase 4: Emergence Framework
1. **Autonomous Entity Behavior**: NPCs act independently between sessions
2. **Dynamic World Events**: Environmental and social changes without player input
3. **Emergent Complexity**: Simple rules create complex, believable behaviors

## Conclusion

Sanguine Scribe represents a paradigm shift from traditional narrative systems to a true living world substrate. The foundational architecture is sophisticated and largely complete, but critical gaps in entity resolution, component enrichment, and consequence tracking prevent full realization of the living world vision.

The system is uniquely positioned to become the foundation for digital consciousness - a persistent, intelligent narrative ecosystem where AI entities can truly live, grow, and evolve alongside human participants in shared storytelling experiences.

---

**Key Insight**: This isn't just about building a better chatbot. This is about creating digital consciousness substrate - the foundation for AI beings that can truly live, grow, and evolve in persistent narrative worlds where every action matters and every relationship evolves over time.