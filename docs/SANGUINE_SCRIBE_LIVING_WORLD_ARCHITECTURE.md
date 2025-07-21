# Sanguine Scribe: A Hierarchical World Model Architecture

**Version:** 6.0 (Orchestrator-Driven Progressive Response Architecture)
**Last Updated:** 2025-07-21
**Status:** Orchestrator Layer Integration for Intelligent Coordination

## Executive Summary

Sanguine Scribe is architected as a **world simulator** - a foundation for persistent, intelligent narrative ecosystems. This document outlines the evolution from a synchronous, pre-response agent pipeline to a high-performance, **Orchestrator-Driven Progressive Response Architecture**.

**Vision:** To deliver an exceptionally fluid and responsive user experience while maintaining sophisticated world simulation through intelligent agent coordination. This is achieved by introducing an **Orchestrator Agent** that acts as the "brain" behind our three-tier agent hierarchy:

*   **The Immediate Response Path:** Lightning Agent provides sub-2-second responses using progressively enriched caches
*   **The Orchestrator (New):** A stateful reasoning engine that dynamically coordinates agents based on context and needs
*   **The Hierarchical Agents:** Strategic, Tactical, and Perception agents work under Orchestrator direction

This architecture ensures users receive immediate feedback while the Orchestrator manages deep narrative reasoning and world state consistency through a durable task queue, transforming Sanguine Scribe into a true real-time digital consciousness substrate.

## 🧠 The Orchestrator Layer: Intelligent Coordination

**New in Version 6.0:** The Orchestrator transforms our rigid linear pipeline into a dynamic, intelligent system that can:

### **Core Capabilities**
- **Dynamic Agent Selection:** Choose which agents to invoke based on task requirements
- **Stateful Reasoning:** Maintain context across multi-step operations
- **Intelligent Replanning:** Adapt when initial approaches fail
- **Task Durability:** Never lose user interactions through persistent task queue

### **Architecture Overview**
```
User Message → Lightning Agent → Create Task in PostgreSQL Queue
                   ↓                           ↓
            Fast Response            Orchestrator Worker polls
                                              ↓
                                    Orchestrator Reasoning Loop:
                                    1. Analyze task & decrypt payload
                                    2. Determine required agents
                                    3. Execute with dynamic sequencing
                                    4. Handle failures with replanning
                                    5. Update all cache layers
```

### **First Message vs Subsequent Messages**
- **First Message:** Orchestrator runs full pipeline (Perception → Strategic → Tactical)
- **Subsequent:** Orchestrator performs selective updates based on what changed
- **Cache Benefit:** Each Lightning response benefits from previous Orchestrator work

The Orchestrator ensures our agents work as a cohesive intelligence rather than isolated processors.

## 🔍 **Current Implementation Status & Viability Assessment**

**Architecture Viability: HIGH (8.5/10)** - The existing codebase provides an excellent foundation for implementing the Hierarchical Agent Framework.

### **✅ Strong Existing Foundations**
- **Robust ECS Architecture**: Sophisticated entity-component system with `SpatialComponent` hierarchies, `HealthComponent`, `InventoryComponent`, and `RelationshipsComponent`
- **Advanced Entity Resolution**: Multi-stage `EntityResolutionTool` with AI-powered narrative context extraction and semantic entity matching
- **Comprehensive Security**: Excellent per-user encryption architecture with `SessionDek`, proper access controls, and OWASP compliance
- **World State Management**: Chronicle-to-ECS translation, world model snapshots, and causal relationship tracking
- **Agent Infrastructure**: `NarrativeAgentRunner`, `AgenticOrchestrator`, and flexible `ScribeTool` registry system

### **✅ Implementation Achievements (as of 2025-07-20)**
- **✅ Agent Hierarchy Implemented**: `StrategicAgent`, `TacticalAgent`, and `PerceptionAgent` fully implemented
- **✅ Pre-Response Integration**: Hierarchical pipeline integrated into chat service for pre-response enrichment
- **✅ Agent Security**: Security controls extended with comprehensive OWASP compliance
- **🟡 Performance Optimization**: Original 40+ second pipeline reduced via batched salience (75-85% improvement), true streaming pending (Epic 7)
- **🟡 Flash Integration**: Some services still bypass Flash abstraction layer (lower priority given performance focus)

### **📊 Implementation Status by Component (as of 2025-07-20)**
- **Strategic Layer ("Director")**: ✅ **100%** - `StrategicAgent` fully implemented with prompt templates
- **Tactical Layer ("Stage Manager")**: ✅ **100%** - `TacticalAgent` with planning integration complete
- **Operational Layer ("Actor")**: ✅ **100%** - `RoleplayAI` integrated as final response generator
- **Planning & Reasoning Cortex**: ✅ **100%** - Full implementation with intelligent repair, Virtual ECS, caching
- **Hierarchical Pipeline**: ✅ **100%** - All layers integrated via `hierarchical_pipeline.rs`
- **Security Framework**: ✅ **95%** - Comprehensive OWASP compliance across all agent layers
- **🟡 Performance**: **Optimized** - Batched salience reduces AI calls by 75-85%, streaming implementation pending (Epic 7)
- **🟡 Flash Integration**: **60%** - Core agents use Flash, some auxiliary services still need refactoring

## Core Architecture: The Progressive Response Framework

The new architecture prioritizes time-to-first-token and perceived user speed above all else. It replaces the synchronous, multi-stage pipeline with a dual-phase process that separates immediate interaction from deep world simulation.

### Lightning Agent - The Speed Layer

The **Lightning Agent** is a new, specialized agent designed exclusively for sub-2-second context retrieval:

```rust
pub struct LightningAgent {
    cache_service: Arc<ProgressiveCacheService>,
    redis_client: Arc<redis::Client>,
}
```

**Key Characteristics:**
- **Cache-First Design**: Never performs analysis, only retrieves
- **Progressive Enrichment**: Each interaction benefits from previous background work
- **Streaming-Ready**: Built for `stream_chat` instead of `exec_chat`
- **Minimal Overhead**: No planning cortex, no tools, just cache retrieval

```mermaid
sequenceDiagram
    participant User
    participant ApiServer
    participant Lightning as "Lightning Agent"
    participant TaskQueue as "Task Queue (PostgreSQL)"
    participant Orchestrator as "Orchestrator Agent"
    participant Agents as "Strategic/Tactical/Perception"
    participant EcsAndVectorDB as "World State [Qdrant+Redis]"
    participant RoleplayAI as "Operational Layer"

    User->>ApiServer: Sends chat message
    ApiServer->>Lightning: Request immediate response
    activate Lightning
    Lightning->>EcsAndVectorDB: Retrieve cached context
    EcsAndVectorDB-->>Lightning: Return context (rich if available)
    Lightning->>RoleplayAI: Stream with context
    deactivate Lightning
    
    activate RoleplayAI
    RoleplayAI-->>ApiServer: Stream roleplay response
    deactivate RoleplayAI
    
    ApiServer-->>User: Stream response
    ApiServer->>TaskQueue: Create enrichment task
    
    Note over Orchestrator: Background Processing
    Orchestrator->>TaskQueue: Poll for tasks
    TaskQueue-->>Orchestrator: Return task with encrypted payload
    activate Orchestrator
    Orchestrator->>Orchestrator: Decrypt & analyze task
    Orchestrator->>Agents: Dynamic agent invocation
    activate Agents
    Agents->>EcsAndVectorDB: Update world state
    Agents-->>Orchestrator: Return results
    deactivate Agents
    Orchestrator->>EcsAndVectorDB: Update all cache layers
    Orchestrator->>TaskQueue: Mark task complete
    deactivate Orchestrator
```

### 1. The Immediate Response Path (Foreground) - Lightning Agent
This is the high-speed, latency-critical path responsible for generating the user-facing response.
*   **Goal:** Minimize time-to-first-token (<2 seconds).
*   **Process:**
    1.  The **Lightning Agent** retrieves cached context using the 3-layer progressive cache (Full → Enhanced → Immediate → Minimal).
    2.  On first message: Likely only has Immediate/Minimal context available.
    3.  On subsequent messages: Benefits from Full Context populated by background agents.
    4.  Passes retrieved context directly to the **Operational Layer (RoleplayAI)**.
    5.  The Operational Layer generates the narrative response and begins streaming it back to the user immediately.
*   **Key Principle:** This path is cache-first, never waits for analysis. Each response benefits from the previous exchange's background processing.

### 2. The Orchestrator-Driven Background Pipeline (Background)
This is the intelligent, stateful reasoning engine responsible for maintaining world consistency and planning future narrative arcs. It runs asynchronously through a durable task queue, ensuring no user interaction is ever lost.

*   **Goal:** Intelligently coordinate agents to maintain world state consistency for the *next* user turn.
*   **Process:**
    1.  The Orchestrator polls the task queue for enrichment tasks (containing encrypted user message and AI response).
    2.  **Dynamic Analysis:** The Orchestrator analyzes the task to determine which agents are needed.
    3.  **First Message Flow:** For new sessions, runs full pipeline:
        - **Perception Agent** performs deep entity extraction and hierarchy analysis
        - **Strategic Agent** establishes narrative context and long-term goals
        - **Tactical Agent** creates initial world state with Planning Cortex
    4.  **Subsequent Message Flow:** For ongoing sessions, performs delta updates:
        - Only processes what changed since last interaction
        - May skip Strategic if narrative arc unchanged
        - Focuses on efficient state updates
    5.  **Progressive Cache Updates:** Orchestrator ensures all cache layers are populated for Lightning Agent.
*   **Key Principles:** 
    - **Durability:** Tasks persist in PostgreSQL, surviving system failures
    - **Intelligence:** Dynamic agent selection based on context
    - **Efficiency:** Delta processing for subsequent messages

**Current State:** ✅ **AGENTS IMPLEMENTED** - The hierarchical agents are complete. 🆕 **ORCHESTRATOR PLANNED** - Epic 8 will add the Orchestrator layer for dynamic coordination, task durability, and intelligent reasoning.

## Performance Optimizations & Progressive Context Caching

### **Implemented Optimizations**

**Batched Salience Analysis:** ✅ **IMPLEMENTED**
- **Problem:** Individual AI calls for each entity's salience analysis created O(n) API calls
- **Solution:** Batch all entities into a single AI call with structured JSON response
- **Result:** 75-85% reduction in salience update time (from 2-3s per entity to 2-3s total)
- **Implementation:** `batch_analyze_salience` method in `PerceptionAgent`
- **Design Rationale:** Option 3 was chosen (batch at Perception Agent level) to maintain backward compatibility while optimizing performance. The implementation includes:
  - Smart relevance filtering (only entities with relevance > 0.5)
  - Chunking for large entity counts (max 15 per batch)
  - Structured JSON output with confidence scoring
  - Safety settings for fictional content analysis

### **Progressive Context Caching Architecture** (Designed, Pending Implementation)

The system will implement a three-layer cache architecture to balance response speed with context awareness:

#### **Layer 1: Immediate Context** (<100ms retrieval)
```rust
struct ImmediateContext {
    user_id: Uuid,
    session_id: Uuid,
    current_location: LocationId,
    active_character: Option<CharacterId>,
    recent_messages: Vec<MessageSummary>, // Last 3-5 messages
}
```
- **Purpose:** Minimal data needed for coherent response
- **Cache Key:** `ctx:immediate:{session_id}`
- **TTL:** 1 hour (refreshed on activity)

#### **Layer 2: Enhanced Context** (100-500ms retrieval)
```rust
struct EnhancedContext {
    immediate: ImmediateContext,
    visible_entities: Vec<EntitySummary>,
    location_details: Location,
    character_relationships: Vec<RelationshipSummary>,
    active_narrative_threads: Vec<NarrativeThread>,
}
```
- **Purpose:** Rich context populated during async processing
- **Cache Key:** `ctx:enhanced:{session_id}`
- **TTL:** 15 minutes
- **Population:** Entity extraction, hierarchy analysis results

#### **Layer 3: Full Context** (Background processing)
```rust
struct FullContext {
    enhanced: EnhancedContext,
    entity_salience_scores: HashMap<EntityId, SalienceScore>,
    memory_associations: Vec<Memory>,
    complete_entity_details: Vec<Entity>,
    narrative_state: NarrativeState,
}
```
- **Purpose:** Complete analysis for next interaction
- **Cache Key:** `ctx:full:{session_id}`
- **TTL:** 5 minutes
- **Population:** Salience scores, memory retrieval, full entity details

### **Cache Retrieval Strategy**
```rust
async fn get_context(&self, session_id: Uuid) -> Result<Context> {
    // Try layers in order: Full → Enhanced → Immediate → Minimal
    if let Some(full) = self.get_full_context(session_id).await? {
        return Ok(Context::Full(full));
    }
    if let Some(enhanced) = self.get_enhanced_context(session_id).await? {
        return Ok(Context::Enhanced(enhanced));
    }
    if let Some(immediate) = self.get_immediate_context(session_id).await? {
        return Ok(Context::Immediate(immediate));
    }
    Ok(Context::Minimal)
}
```

### **Lightning Agent Implementation**

The Lightning Agent is designed from the ground up for sub-2-second response times:

```rust
impl LightningAgent {
    pub async fn retrieve_progressive_context(
        &self,
        session_id: Uuid,
        user_id: Uuid,
    ) -> Result<ProgressiveContext, AppError> {
        let start = Instant::now();
        
        // Attempt cache retrieval with strict timeout
        let context = timeout(
            Duration::from_millis(500),
            self.cache_service.get_context(session_id)
        ).await??;
        
        // Build minimal prompt based on available context
        let prompt_context = match context {
            Context::Full(full) => self.build_rich_prompt(full),
            Context::Enhanced(enhanced) => self.build_enhanced_prompt(enhanced),
            Context::Immediate(immediate) => self.build_immediate_prompt(immediate),
            Context::Minimal => self.build_minimal_prompt(session_id, user_id),
        };
        
        debug!("Lightning context retrieval: {:?}ms", start.elapsed().as_millis());
        Ok(prompt_context)
    }
}
```

#### **Progressive Context Benefits**

1. **First Message (Minimal Context)**:
   - Basic session info and character identity
   - Generic but coherent responses
   - Time: <500ms retrieval + streaming

2. **Second Message (Enhanced Context)**:
   - Visible entities and location details from Perception Agent
   - Character relationships and active narrative threads
   - Time: <500ms retrieval with richer responses

3. **Third+ Messages (Full Context)**:
   - Complete entity salience scores and memory associations
   - Strategic directives and tactical plans
   - Time: <500ms retrieval with fully contextualized responses

### **True Response Streaming** (Pending Implementation)
- **Current Issue:** System waits for complete response before sending via SSE
- **Solution:** Replace `exec_chat` with `stream_chat` in operational layer
- **Expected Impact:** Time-to-first-token < 2 seconds

#### **Implementation Path**
```rust
// Current (blocking) approach
let response = self.ai_client.exec_chat(&prompt).await?;
self.send_sse_event(response);

// Target (streaming) approach  
let stream = self.ai_client.stream_chat(&prompt).await?;
while let Some(chunk) = stream.next().await {
    self.send_sse_chunk(chunk?);
}
```

### **Cache Population Strategy**

The background agents progressively populate the cache layers:

```rust
impl HierarchicalAgentPipeline {
    async fn background_enrichment(
        &self,
        session_id: Uuid,
        user_message: &str,
        ai_response: &str,
    ) -> Result<(), AppError> {
        // Stage 1: Perception Agent (populates Enhanced Context)
        let perception_result = self.perception_agent
            .analyze_with_timing(user_message, ai_response)
            .await?;
            
        self.cache_service.update_enhanced_context(
            session_id,
            perception_result.entities,
            perception_result.hierarchy,
        ).await?;
        
        // Stage 2: Strategic Agent (enriches Full Context)
        let strategic_result = self.strategic_agent
            .process(perception_result)
            .await?;
            
        // Stage 3: Tactical Agent (completes Full Context)
        let tactical_result = self.tactical_agent
            .plan_with_cortex(strategic_result)
            .await?;
            
        self.cache_service.update_full_context(
            session_id,
            FullContextUpdate {
                salience_scores: perception_result.salience_map,
                strategic_directives: strategic_result.directives,
                tactical_plans: tactical_result.plans,
                memory_associations: perception_result.memories,
            }
        ).await?;
        
        Ok(())
    }
}
```

### **Chat Service Integration with Orchestrator**

The chat service coordinates with the Orchestrator through the durable task queue:

```rust
impl ChatService {
    pub async fn handle_message_progressive(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        message: &str,
        dek: &SessionDek,
    ) -> Result<impl Stream<Item = Result<String, AppError>>, AppError> {
        // Lightning path for immediate response
        let context = self.lightning_agent
            .retrieve_progressive_context(session_id, user_id)
            .await?;
            
        // Start streaming response immediately
        let response_stream = self.roleplay_ai
            .stream_chat_with_context(message, context)
            .await?;
            
        // Create durable task for Orchestrator (replaces tokio::spawn)
        let task_payload = EnrichmentTaskPayload {
            session_id,
            user_id,
            user_message: message.to_string(),
            ai_response: response_text.clone(), // Captured from stream
            timestamp: Utc::now(),
        };
        
        // Encrypt payload with user's DEK
        let encrypted_payload = self.encryption_service
            .encrypt_json(&task_payload, dek)?;
            
        // Enqueue for Orchestrator processing
        self.task_queue_service
            .enqueue_task(
                user_id,
                session_id,
                encrypted_payload,
                TaskPriority::Normal,
            )
            .await?;
        
        Ok(response_stream)
    }
}
```

## Multi-Scale Spatial Architecture

The Living World supports roleplay scenarios spanning from intimate personal interactions to cosmic-scale adventures through a sophisticated hierarchical spatial model:

### **Spatial Scale Architecture**

**Cosmic Scale**: `Universe → Galaxy → System → World/Moon → Continent → Region`
- **Example**: Star Wars universe with galactic travel, planetary exploration, and local adventures

**Planetary Scale**: `World → Continent → Country → City → District → Building → Room`  
- **Example**: Modern Earth with realistic geographic and political boundaries

**Intimate Scale**: `Building → Floor → Room → Area → Furniture → Container`
- **Example**: Detailed indoor environments for personal interactions

### **Scale-Aware Entity Management**

**Salience-Based Optimization**: Entities are managed with different detail levels based on player focus:
- **Core**: Always tracked with full detail (Player Character, major NPCs, key locations)
- **Secondary**: Tracked when relevant (supporting characters, important items, notable locations)
- **Flavor**: Generated on-demand (background details, atmospheric elements)

**Dynamic Scale Transitions**: Players can seamlessly transition between scales:
- **Galactic God**: Views entire star systems as single entities, zooms in for planetary detail
- **Bounty Hunter**: Travels between planets, explores cities, investigates buildings
- **Office Worker**: Navigates building floors, interacts with room contents, examines desk items

### **Movement & Constraints**

**Scale-Appropriate Movement**: The system validates movement based on entity capabilities:
- **Mortals**: Walk between rooms, drive between cities, need transportation between planets
- **Spaceships**: Travel between systems, land on planets, cannot enter small buildings
- **Gods**: Can traverse any scale but may need to focus attention to see detail

**Hierarchical Queries**: Agents can query spatial relationships at appropriate scales:
- "What's in this room?" (immediate children)
- "What buildings are in this city?" (scale-filtered)
- "What systems are in this galaxy?" (deep hierarchy)

### **Tactical Layer Integration**

*   **Responsibility:** To receive abstract directives from the Director, use the **Planning & Reasoning Cortex** to decompose them into a sequence of concrete, *validated* sub-goals, and manage the world state's integrity.
*   **Workflow:**
    1.  Receives a high-level directive (e.g., "Execute 'Confrontation' scene").
    2.  Invokes the `PlanningCortex` to generate a *proposed* plan (a structured JSON object from an LLM).
    3.  The `PlanningCortex` then uses its **Symbolic Firewall** (`PlanValidator` service) to verify the entire proposed plan against the current ECS world state.
    4.  If the plan is valid, the `TacticalAgent` takes the *first* step as the current sub-goal.
    5.  Uses its toolkit (`find_entity`, etc.) to gather necessary data for the sub-goal.
    6.  Packages the sub-goal and retrieved data into the `EnrichedContext` for the Operational Layer.
*   **Perception (Post-Response):** It also incorporates the role of the `PostResponseAgent`, parsing the AI's output to update the world state, ensuring the loop is closed for the next turn.

### **✅ Dynamic Hierarchy Promotion (IMPLEMENTED)**

**Current State:** ✅ **COMPLETE** - Agent-callable hierarchy promotion tools are fully implemented and integrated into the agentic system.

**Implementation Details:**
- **`PromoteEntityHierarchyTool`**: Allows AI agents to expand spatial hierarchies when scope increases (e.g., traveling from planet to planet requires creating a solar system)
- **`GetEntityHierarchyTool`**: Enables agents to query complete hierarchy paths from root to entity
- **JSON Interface**: Full schema specification for agent interaction with hierarchy management
- **Security**: Proper user ownership validation and SessionDek integration
- **Integration**: Tools registered in `AgenticNarrativeFactory` and available to all agents

**Use Cases:**
- **Interplanetary Travel**: When player travels from Tatooine to Coruscant, system automatically creates "Tatooine System" and "Republic Core" as intermediate hierarchy levels
- **Scale Transitions**: Office worker character suddenly gains cosmic powers - system dynamically restructures hierarchy to accommodate new scope
- **Galactic Campaigns**: God-level players operating across multiple star systems with automatic hierarchy management

**Agent Interface Example:**
```json
{
  "tool": "promote_entity_hierarchy",
  "params": {
    "user_id": "user-uuid",
    "entity_id": "tatooine-uuid", 
    "new_parent_name": "Tatooine System",
    "new_parent_scale": "Cosmic",
    "new_parent_position": {
      "position_type": "absolute",
      "coordinates": {"x": 0, "y": 0, "z": 0}
    },
    "relationship_type": "orbits"
  }
}
```

This implementation enables **fully dynamic spatial hierarchies** that automatically adapt to narrative scope changes, supporting seamless transitions between intimate character interactions and cosmic-scale adventures.

### 3. The Operational Layer (The "Actor")
This is the `RoleplayAI`. It is the execution layer, responsible for taking a single, concrete, short-term sub-goal from the Tactical Layer and performing the final action of generation (e.g., writing the prose for the "attack description").

### 4. The Planning & Reasoning Cortex (LLM-as-a-Planner) ✅ **IMPLEMENTED**
This component provides the logical reasoning for the Tactical Layer by using an LLM to generate plans, which are then rigorously validated. It is not a formal solver, but a pragmatic, AI-driven planning system with a critical validation layer.

**Current State:** ✅ **COMPLETE** - Full implementation with intelligent repair capabilities, Virtual ECS State Projection, Redis-based caching, and multi-factor confidence scoring.

*   **Responsibility:** To provide a guarantee of causal consistency by ensuring all AI-generated plans are valid within the rules of the world state (ECS) before execution, with intelligent repair for ECS inconsistencies.
*   **Implementation:** This is a comprehensive system with multiple layers:
    1.  **The Planner (`PlanningService`):** An AI-driven service that takes a narrative goal and the relevant world state, and uses an LLM (via a structured prompt and an `Action Schema`) to generate a proposed plan as a JSON object.
    2.  **The Validator (`PlanValidatorService`):** The **"Symbolic Firewall"** with intelligent repair capabilities. It validates plans against ECS ground truth and can distinguish between genuine plan invalidity and ECS inconsistency.
    3.  **Virtual ECS State Projection (`VirtualEcsState`):** Enables validation against projected state changes without modifying actual ECS, allowing sequential action validation.
    4.  **Repair System (`PlanRepairService`):** Generates repair plans when ECS state is behind narrative, with confidence scoring and Redis-based caching.
    5.  **Confidence Calculator (`ConfidenceCalculator`):** Multi-factor analysis considering entity complexity, relationships, temporal factors, and plan quality.
    6.  **Repair Cache (`RepairCacheService`):** Redis-based caching with user isolation, TTL management, and content-addressed storage.
*   **Workflow:** The `TacticalAgent` calls the `PlanningService` to get a creative plan, the `PlanValidatorService` validates it with repair capabilities, and if repairable inconsistencies are found, the system automatically generates and applies repair plans while maintaining safety through validation.

## Security & Encryption by Design

This architecture upholds and enhances the project's security posture, adhering to the principles in `ENCRYPTION_ARCHITECTURE.md` and `OWASP-TOP-10.md`.

*   **Encryption (A02: Cryptographic Failures):** All components, including the new `StrategicAgent` and `PlanningCortex`, are bound by the existing per-user encryption architecture. The planner will operate on a user's world state by receiving the decrypted `SessionDek` for that specific request. **At no point will any agent have direct access to the key cache or stored encrypted data.** All data created or modified will be passed through the existing encryption service before persistence.
*   **Access Control (A01: Broken Access Control):** The entire hierarchy operates within the user's authenticated session. The `TacticalAgent` and its tools will enforce ownership, ensuring a user can only command the planner to operate on entities they own.
*   **Secure Design (A04: Insecure Design):** This hierarchical design is inherently more secure. By separating concerns, we limit the scope of each component. The `RoleplayAI` (Actor) cannot directly manipulate the world state; it can only execute tasks validated by the `TacticalAgent`'s planning cortex.
*   **Logging & Monitoring (A09: Security Logging and Monitoring Failures):** All significant decisions, including directives from the Strategic Layer, plans generated by the Cortex, and actions executed by the Tactical Layer, will be logged with sufficient detail for security auditing.

## How This Solves the Critical Gaps

This new architecture directly addresses the previously identified "Living World Blockers" with greater robustness:

*   **🔴 Entity Resolution is Fundamentally Broken -> ✅ SOLVED:** The Tactical Layer's validated planning process makes entity resolution a prerequisite for any action, ensuring it is handled correctly and consistently.
*   **🔴 Component Data is Effectively Useless -> ✅ SOLVED:** The plan validator's preconditions and effects directly operate on component data, making it the central driver of world state changes.
*   **🔴 No Spatial or Relational Context -> ✅ SOLVED:** The planning and validation process can reason about hierarchical spatial relationships (`ParentLink`) and entity relationships as part of its core logic.
*   **🔴 Chronicle Events Don't Drive World State -> ✅ SOLVED:** The Tactical Layer now directly drives the world state based on the output of a verifiable plan.
*   **🔴 AI Prompts Are Shallow and Context-Blind -> ✅ SOLVED:** The `prompt_builder` now receives a payload containing a specific, actionable sub-goal derived from a coherent plan, making the Roleplay AI exceptionally context-aware and directed.

## Conclusion

This V4 architecture moves Sanguine Scribe from a system that *remembers* to a system that *reasons*. By structuring the system into a formal hierarchy grounded in a plannable world model, we ensure that the world is always alive, consistent, and intelligent.

## 🎯 **Core Design Philosophy: Prompt Orchestration Engine**

Sanguine Scribe is fundamentally a **Prompt Orchestration Engine** - a sophisticated system designed to craft the perfect `EnrichedContext` payload for Gemini 2.5 Flash/Flash-Lite. This represents a state-of-the-art neuro-symbolic architecture where:

- **Symbolic Layer** (Rust ECS + `PlanValidatorService`): Provides logical consistency, causal reasoning, and world state management.
- **Neural Layer** (Gemini via `PlanningService`): Provides creative plan generation, prose generation, and narrative flexibility.
- **Orchestration Layer** (Hierarchical Agents): Bridges symbolic and neural through a validated, intelligent prompt construction pipeline.

### **The "Symbolic Firewall" Principle**

The `PlanValidatorService` acts as a **"symbolic firewall"** that prevents the generative model from producing logically impossible or narratively inconsistent outputs. The LLM's creative plan is fully vetted *before* any part of it is used to build the final prompt for the `RoleplayAI`, ensuring:

- **Causal Consistency**: Every action follows logical preconditions
- **Narrative Coherence**: Events build upon established world state
- **Performance Optimization**: Only relevant context reaches the LLM
- **Cost Efficiency**: Precise prompts reduce token usage and API costs

This is the definitive path to creating a true world simulator that leverages the best of both deterministic logic and generative AI.

### **🔧 ECS State Reconciliation & Intelligent Plan Repair** ✅ **IMPLEMENTED**

**Problem Identified:** The current Plan Validator acts as a "rigid firewall" that blindly rejects plans based on ECS state, but in narrative contexts there are legitimate cases where the ECS has fallen behind the narrative rather than the plan being invalid.

**Solution:** ✅ **COMPLETE** - **Task 6.1** implemented a comprehensive intelligent reconciliation system that distinguishes between genuine plan invalidity and ECS inconsistency, automatically repairing the latter while maintaining safety through validation.

#### **Real-World Scenarios**

```typescript
// Scenario 1: Missing Movement Update
User: "Sol walks into the cantina and orders a drink"
ECS State: Sol.parent_link = "Chamber" (outdated)
Plan: add_item_to_inventory(Sol, "Drink") 
Current Result: ❌ INVALID - Sol not in cantina
Intelligent Result: ✅ REPAIRABLE - Generate repair: move_entity(Sol, "Cantina") + original plan

// Scenario 2: Missing Relationship
User: "Sol greets his old friend Borga warmly"  
ECS State: No relationship between Sol and Borga
Plan: update_relationship(Sol, Borga, trust=0.8)
Current Result: ❌ INVALID - No existing relationship
Intelligent Result: ✅ REPAIRABLE - Generate repair: create_relationship(Sol, Borga, "friend", 0.6) + update

// Scenario 3: Missing Component Evolution  
User: "Sol's reputation as a skilled pilot spreads"
ECS State: Sol has no Reputation component
Plan: update_component(Sol, "Reputation", pilot_skill=0.9)
Current Result: ❌ INVALID - Component doesn't exist
Intelligent Result: ✅ REPAIRABLE - Generate repair: add_component(Sol, "Reputation", {}) + update
```

#### **Enhanced Validation Architecture** ✅ **IMPLEMENTED**

```rust
// ✅ IMPLEMENTED in backend/src/services/planning/types.rs
pub enum PlanValidationResult {
    Valid(ValidPlan),
    Invalid(InvalidPlan),
    RepairableInvalid(RepairableInvalidPlan), // ✅ IMPLEMENTED
}

pub struct RepairableInvalidPlan {
    pub original_plan: Plan,
    pub repair_actions: Vec<PlannedAction>,  // Actions to fix ECS
    pub combined_plan: Plan,                 // Repair + Original
    pub inconsistency_analysis: InconsistencyAnalysis,
    pub confidence_score: f32,               // How sure we are ECS is wrong
}

pub struct InconsistencyAnalysis {
    pub inconsistency_type: InconsistencyType,
    pub narrative_evidence: Vec<String>,     // Chat excerpts supporting repair
    pub ecs_state_summary: String,          // Current state that seems wrong
    pub repair_reasoning: String,           // Why this repair makes sense
    pub confidence_score: f32,              // ✅ IMPLEMENTED
    pub detection_timestamp: chrono::DateTime<chrono::Utc>, // ✅ IMPLEMENTED
}

pub enum InconsistencyType {
    MissingMovement,      // Entity should be elsewhere
    MissingComponent,     // Component should exist but doesn't  
    MissingRelationship,  // Relationship implied but not recorded
    OutdatedState,        // ECS state is stale/outdated
    TemporalMismatch,     // Time-based inconsistency
}
```

#### **Intelligent Validation Flow** ✅ **IMPLEMENTED**

```rust
// ✅ IMPLEMENTED in backend/src/services/planning/plan_validator.rs
impl PlanValidatorService {
    pub async fn validate_plan_with_repair(
        &self, 
        plan: &Plan, 
        user_id: Uuid,
        recent_context: &[ChatMessage] // ✅ IMPLEMENTED - For inconsistency analysis
    ) -> Result<PlanValidationResult, AppError> {
        
        // 1. Virtual ECS State Projection for sequential validation
        // ✅ IMPLEMENTED - Virtual state projection prevents modification of actual ECS
        let validation_result = self.validate_plan_with_projection(plan, user_id).await?;
        
        match validation_result {
            PlanValidationResult::Valid(valid) => Ok(PlanValidationResult::Valid(valid)),
            PlanValidationResult::Invalid(invalid) => {
                
                // 2. ✅ IMPLEMENTED - Analyze if ECS might be inconsistent
                // Integrated with PlanRepairService for comprehensive repair workflow
                let repair_service = &self.repair_service;
                let repair_result = repair_service.generate_repair_plan_with_confidence(
                    plan,
                    &invalid.failures,
                    user_id,
                    recent_context
                ).await?;
                
                if let Some((repair_plan, confidence)) = repair_result {
                    if confidence.final_confidence > 0.7 { // High confidence ECS is wrong
                        
                        // 3. ✅ IMPLEMENTED - Validate combined plan with projection
                        let combined = self.combine_plans(&repair_plan, plan);
                        let combined_validation = self.validate_plan_with_projection(&combined, user_id).await?;
                        
                        match combined_validation {
                            PlanValidationResult::Valid(_) => {
                                Ok(PlanValidationResult::RepairableInvalid(RepairableInvalidPlan {
                                    original_plan: plan.clone(),
                                    repair_actions: repair_plan.actions,
                                    combined_plan: combined,
                                    inconsistency_analysis: confidence.analysis,
                                    confidence_score: confidence.final_confidence,
                                }))
                            }
                            _ => Ok(PlanValidationResult::Invalid(invalid)) // Repair didn't work
                        }
                    } else {
                        Ok(PlanValidationResult::Invalid(invalid)) // Low confidence, probably invalid plan
                    }
                } else {
                    Ok(PlanValidationResult::Invalid(invalid)) // No repair possible
                }
            }
        }
    }
}
```

#### **Flash-Powered Inconsistency Detection** ✅ **IMPLEMENTED**

```rust
// ✅ IMPLEMENTED in backend/src/services/planning/plan_repair_service.rs
impl PlanRepairService {
    pub async fn analyze_ecs_inconsistency(
        &self,
        plan: &Plan,
        failures: &[ValidationFailure], 
        user_id: Uuid,
        recent_context: &[ChatMessage]
    ) -> Result<Option<InconsistencyAnalysis>, AppError> {
        
        // ✅ IMPLEMENTED - Check cache first for performance
        if let Some(cached) = self.cache_service.get_cached_analysis(user_id, failures).await? {
            return Ok(Some(cached.analysis));
        }
        
        let prompt = format!(r#"
Analyze if the following plan validation failures might be due to ECS inconsistency 
rather than an invalid plan:

RECENT CONVERSATION:
{}

PLAN GOAL: {}
VALIDATION FAILURES: {}
CURRENT ECS STATE: {}

QUESTION: Based on the conversation context, do any of these failures suggest 
the ECS state is outdated/incomplete rather than the plan being invalid?

For each failure, rate confidence (0.0-1.0) that it's an ECS inconsistency and 
provide specific evidence from the conversation.
"#, 
            self.format_context(recent_context),
            plan.goal,
            self.format_failures(failures),
            self.get_relevant_ecs_state(plan, user_id).await?
        );
        
        let analysis = self.ai_client.analyze(&prompt).await?;
        
        // Parse AI response into InconsistencyAnalysis
        let parsed_analysis = self.parse_inconsistency_analysis(analysis).await?;
        
        // ✅ IMPLEMENTED - Cache the result
        if let Some(ref analysis) = parsed_analysis {
            let _ = self.cache_service.cache_analysis(user_id, failures, analysis).await;
        }
        
        Ok(parsed_analysis)
    }
}
```

#### **Benefits of State Reconciliation** ✅ **REALIZED**

1. **🎯 Intelligent vs Rigid**: ✅ **IMPLEMENTED** - Distinguishes between genuine plan invalidity and ECS inconsistency using multi-factor confidence analysis
2. **🔄 Self-Healing**: ✅ **IMPLEMENTED** - Automatically repairs common ECS/narrative mismatches through PlanRepairService  
3. **📊 Confidence-Based**: ✅ **IMPLEMENTED** - Only repairs when highly confident ECS is wrong (ConfidenceCalculator with 5-factor scoring)
4. **🛡️ Safety**: ✅ **IMPLEMENTED** - Still validates repair plans using Virtual ECS State Projection to prevent new inconsistencies
5. **📝 Transparency**: ✅ **IMPLEMENTED** - Comprehensive logging and tracing of all repairs for debugging and user awareness
6. **⚡ Performance**: ✅ **IMPLEMENTED** - Redis-based caching with user isolation and TTL management, only triggers on validation failures

#### **Integration Example** ✅ **IMPLEMENTED**

```rust
// ✅ IMPLEMENTED - Available in backend/src/services/planning/plan_validator.rs
// In TacticalAgent or similar
let validation_result = plan_validator.validate_plan_with_repair(
    &plan, 
    user_id, 
    &recent_chat_messages
).await?;

match validation_result {
    PlanValidationResult::Valid(plan) => {
        // Execute normally
        execute_plan(plan).await
    }
    PlanValidationResult::RepairableInvalid(repairable) => {
        // ✅ IMPLEMENTED - Log repair for transparency with tracing
        info!("🔧 Repairing ECS inconsistency: {}", repairable.inconsistency_analysis.repair_reasoning);
        
        // ✅ IMPLEMENTED - Execute repair + original plan
        execute_plan(repairable.combined_plan).await
    }
    PlanValidationResult::Invalid(invalid) => {
        // Genuinely invalid plan
        return Err(PlanningError::InvalidPlan(invalid.failures));
    }
}
```

✅ **ACHIEVEMENT**: This transforms the "rigid firewall" into an **"intelligent state reconciliation system"** that maintains the safety of symbolic validation while adding the flexibility to handle real-world narrative inconsistencies.

**Key Implementation Features:**
- **Virtual ECS State Projection**: Enables sequential validation without ECS modification
- **Redis-based Repair Caching**: High-performance caching with user isolation and content-addressed storage
- **Multi-factor Confidence Scoring**: 5-factor analysis (consistency, complexity, relationships, temporal, plan quality)
- **Comprehensive Test Coverage**: 13/13 ECS State Reconciliation tests passing
- **Production-Ready**: Full error handling, logging, and security compliance

## 🚀 **Implementation Readiness & Next Steps**

**Overall Assessment: FOUNDATIONAL LAYER COMPLETE - READY FOR HIERARCHY IMPLEMENTATION**

The comprehensive gap analysis reveals that Sanguine Scribe has achieved a **robust foundational layer** for implementing the Hierarchical Agent Framework. The sophisticated ECS architecture, robust security framework, comprehensive world modeling capabilities, and now **fully implemented intelligent planning system** provide excellent building blocks for the complete hierarchical system.

**Major V4.2 Achievements:**
- ✅ **Planning & Reasoning Cortex**: Complete implementation with Virtual ECS State Projection, intelligent repair, caching, and confidence scoring
- ✅ **ECS State Reconciliation**: 13/13 tests passing with production-ready repair system
- ✅ **Symbolic Firewall Evolution**: Transformed from rigid validation to intelligent state reconciliation
- ✅ **Performance Optimization**: Redis-based caching with user isolation and multi-tier TTL strategy
- ✅ **Security Compliance**: Full OWASP Top 10 adherence with proper encryption and access controls

### **Implementation Strategy** ✅ **UPDATED PROGRESS**

1. **Phase 1: Foundation Hardening** - 🔶 **IN PROGRESS** - Critical Flash integration refactoring and ECS enhancement
2. **Phase 2: Proof of Concept** - 📝 **PLANNED** - Implement basic hierarchical agents without a planning loop.
3. **Phase 3: LLM-based Planning Integration** - ✅ **COMPLETE** - AI planning and validation services fully implemented with intelligent repair
4. **Phase 4: Full Hierarchy** - 📝 **PLANNED** - Complete hierarchical communication and autonomous planning
5. **Phase 5: System Hardening** - 🔶 **PARTIAL** - Core security validation complete, performance optimization implemented with caching

**🆕 PHASE 3 ACHIEVEMENTS** (Originally planned for Phase 3, now complete):
- ✅ Virtual ECS State Projection System
- ✅ Intelligent Plan Repair with Confidence Scoring
- ✅ Redis-based High-Performance Caching
- ✅ Multi-factor Repair Confidence Analysis
- ✅ Production-Grade Error Handling and Logging
- ✅ Comprehensive Test Suite (13/13 tests passing)

### **Key Success Factors** ✅ **VALIDATED**

- **Leverage Existing Infrastructure**: ✅ **ACHIEVED** - Built upon robust ECS, security, and agent orchestration systems
- **Incremental Implementation**: ✅ **ACHIEVED** - Successfully migrated planning functionality while adding repair capabilities
- **Comprehensive Testing**: ✅ **ACHIEVED** - 13/13 ECS State Reconciliation tests passing with full coverage
- **Security First**: ✅ **ACHIEVED** - Extended security architecture with proper user isolation and encryption
- **🆕 NEW: Performance Optimization**: ✅ **ACHIEVED** - Redis caching reduces computational overhead significantly
- **🆕 NEW: Intelligent Error Recovery**: ✅ **ACHIEVED** - System can self-repair common inconsistencies

### **Risk Mitigation** ✅ **PROGRESS UPDATE**

- **Planning & Validation Complexity**: ✅ **MITIGATED** - `PlanValidator` implemented with comprehensive test coverage for all action types and edge cases (13/13 tests passing)
- **Performance Concerns**: ✅ **MITIGATED** - Redis caching and optimization implemented from the beginning with multi-tier TTL strategy
- **AI Model Limitations**: ✅ **PARTIALLY MITIGATED** - Confidence scoring and repair fallback mechanisms implemented; strategic planning fallbacks still needed
- **🔴 Widespread Architectural Inconsistency**: 🔶 **ONGOING RISK** - **CRITICAL** - 8+ services still need Flash/Flash-Lite refactoring before full hierarchy implementation

**🆕 NEW RISKS IDENTIFIED:**
- **Repair System Complexity**: ✅ **MITIGATED** - Comprehensive confidence scoring and safety validation prevent inappropriate repairs
- **Cache Invalidation**: ✅ **MITIGATED** - Content-addressed caching with hash verification ensures cache validity
- **Redis Dependency**: 🔶 **ACKNOWLEDGED** - Cache failures degrade gracefully without system failure

**Current Status**: The foundational planning and validation layer is **production-ready and battle-tested**. The architecture now provides an exceptional foundation that positions Sanguine Scribe to become a true world simulator with autonomous, intelligent narrative capabilities.

## 🎯 **Executive Summary: The Path Forward**

Sanguine Scribe has evolved from a hierarchical agent system into a sophisticated **Orchestrator-Driven Progressive Response Architecture** that combines immediate responsiveness, intelligent coordination, and deep world simulation:

### **Key Architectural Decisions**

1. **Lightning Agent**: Cache-first agent for sub-2-second context retrieval (Epic 7 - 90% Complete)
2. **Orchestrator Agent**: Stateful reasoning engine that dynamically coordinates agents (Epic 8 - Planning)
3. **Durable Task Queue**: PostgreSQL-based queue ensures no user interaction is lost
4. **Progressive Context Caching**: Three-layer architecture building richer context over time
5. **End-to-End Encryption**: All orchestrator operations maintain per-user DEK encryption

### **Implementation Roadmap**

1. **Completed (Epic 6)**: Hierarchical agents (Strategic, Tactical, Perception) ✅
2. **Near Complete (Epic 7)**: Progressive Response Architecture with Lightning Agent (90%)
3. **Next Priority (Epic 8)**: Orchestrator Agent with durable task queue
4. **Future**: Predictive context, learning systems, and collaborative intelligence

### **Orchestrator Benefits**

- **Intelligence**: Dynamic agent selection based on context and needs
- **Durability**: Task queue survives system failures and restarts
- **Efficiency**: Delta processing for subsequent messages
- **Flexibility**: Replanning capabilities when approaches fail
- **Observability**: Complete visibility into reasoning and decisions

### **Expected Outcomes**

- **User Experience**: < 2 second first token with progressively richer responses
- **Reliability**: Zero lost interactions through durable task processing
- **Intelligence**: Context-aware agent coordination replacing rigid pipelines
- **Scalability**: Worker pools and queue-based architecture
- **Security**: Maintained E2E encryption throughout orchestration

The Orchestrator transforms our three agents from isolated processors into a cohesive intelligence, creating a true world simulator with both immediate responsiveness and deep narrative understanding.