# Sanguine Scribe: Living World Implementation Roadmap (V8 - Hierarchical Model)

**Vision:** To execute a methodical, test-driven migration to a **Hierarchical World Model**. This roadmap details the establishment of a rich world ontology (The Atlas), the integration of a formal planning engine (The Blueprint), the development of tactical and operational agents (The Puppet), and the creation of a strategic, autonomous narrative system (The Autonomic System), with security and testability as foundational pillars.

## 📋 **Definition of Done**

**Task Completion Criteria:** A task is considered complete ONLY when ALL of the following conditions are met:

1. **✅ Code Compiles Successfully**
   - `cargo check --all-targets` passes without errors
   - All relevant modules and dependencies compile cleanly
   - No compilation warnings in new code

2. **✅ All Tests Pass**
   - Unit tests: `cargo test <module_name>` passes
   - Integration tests: `cargo test --test <test_name>` passes  
   - Security tests: All OWASP Top 10 related tests pass
   - Performance tests: No significant performance regressions

3. **✅ OWASP Top 10 Security Compliance**
   - **A01 (Broken Access Control)**: All new functionality enforces proper user ownership and authorization
   - **A02 (Cryptographic Failures)**: All data operations use proper `SessionDek` encryption
   - **A03 (Injection)**: All user inputs are properly sanitized and validated
   - **A04 (Insecure Design)**: Security controls are designed into the architecture from the start
   - **A05 (Security Misconfiguration)**: All new services have secure default configurations
   - **A06 (Vulnerable Components)**: No introduction of vulnerable dependencies
   - **A07 (Authentication Failures)**: All authentication mechanisms are properly implemented
   - **A08 (Data Integrity)**: All data modifications are properly validated and logged
   - **A09 (Logging/Monitoring)**: All security-relevant events are properly logged
   - **A10 (SSRF)**: All external requests are properly validated and restricted

4. **✅ Code Quality Standards**
   - Follows existing code patterns and conventions
   - Comprehensive error handling with `AppError`
   - Proper use of `tracing` for logging
   - Documentation comments for public APIs

5. **✅ Roadmap Checkbox Update**
   - Only after all above criteria are met, the corresponding checkbox in this roadmap may be marked as complete: `[x]`

**❌ Tasks are NOT complete if:**
- Code compiles but tests fail
- Tests pass but OWASP security requirements are not met
- Security tests are not implemented
- Performance significantly degrades
- Error handling is inadequate
- Documentation is missing

## 🔍 **Current State Assessment & Gap Analysis**

**Foundation Viability: HIGH (8.5/10)** - The existing codebase provides excellent building blocks for the hierarchical agent framework.

### **✅ Existing Strong Foundations**
- **ECS Architecture**: Robust entity-component system with sophisticated spatial hierarchies (`SpatialComponent`, container/containable relationships)
- **Entity Resolution**: Multi-stage `EntityResolutionTool` with AI-powered narrative context extraction
- **Security**: Excellent per-user encryption architecture with `SessionDek` and comprehensive access controls
- **World Modeling**: Chronicle-to-ECS translation, comprehensive world state snapshots, and causal relationship tracking
- **Tool Infrastructure**: Flexible `ScribeTool` registry and `NarrativeAgentRunner` orchestration framework

### **🔴 Critical Gaps Identified**
- **Missing Hierarchical Agents**: No `StrategicAgent`, `TacticalAgent`, or `PreResponseAgent`/`PostResponseAgent` classes exist
- **No Formal Planning**: Current system uses LLM-based planning without formal verification (no PDDL/HTN integration)
- **Missing Pre-Response Pipeline**: Agents currently run post-chat; no pre-response enrichment integration
- **No Agent Security Framework**: Security controls need extension to new agent hierarchy

### **🟡 Partial Implementations**
- **Planning Capabilities**: Sophisticated `QueryStrategyPlanner` and action planning exist but lack formal verification
- **Agent Orchestration**: `AgenticOrchestrator` and `NarrativeAgentRunner` provide orchestration patterns but not hierarchical agent communication
- **Spatial Hierarchy**: Components exist but need `ParentLink` and `Salience` tier implementations

## 📋 **Implementation Phases & Risk Assessment**

### **Phase 1: Foundation Hardening (4-6 weeks) - 🟡 MEDIUM RISK**
**Focus:** Critical Flash integration refactoring and ECS foundation completion
- **Epics:** 0 (World Ontology), 1 (Foundational Refactoring with Flash Integration), 2 (Tactical Toolkit)
- **Risk Level:** Medium - extensive refactoring of AI integration patterns across 8+ services
- **Success Criteria:** All hardcoded AI calls replaced with Flash abstractions, existing functionality preserved with enhanced ECS capabilities

### **Phase 2: Proof of Concept (4-6 weeks) - 🟡 MEDIUM RISK**
**Focus:** Implement basic hierarchical agents without formal planning
- **Epics:** 4 (Agent Implementation - Basic version)
- **Risk Level:** Medium - architectural changes to chat service integration
- **Success Criteria:** Basic `TacticalAgent` enriching chat prompts with world state

### **Phase 3: Formal Planning Integration (6-8 weeks) - 🔴 HIGH RISK**
**Focus:** Add symbolic reasoning and formal planning capabilities
- **Epics:** 3 (Planning Cortex)
- **Risk Level:** High - complex integration with external planning frameworks
- **Success Criteria:** PDDL/HTN planner generating verifiable action sequences

### **Phase 4: Full Hierarchy (8-10 weeks) - 🟡 MEDIUM RISK**
**Focus:** Complete the three-layer agent system
- **Epics:** 5 (Strategic Layer & Autonomic Loop)
- **Risk Level:** Medium - AI capability requirements for strategic planning
- **Success Criteria:** Full Strategic → Tactical → Operational pipeline with autonomous re-planning

### **Phase 5: System Hardening (2-3 weeks) - 🟢 LOW RISK**
**Focus:** Security validation and performance optimization
- **Epics:** 6 (Full System Validation)
- **Risk Level:** Low - builds on existing security and testing infrastructure
- **Success Criteria:** Production-ready system with comprehensive security audit

### **🚨 High-Risk Areas Requiring Special Attention**
1. **🔴 Comprehensive Flash Integration**: 8+ services with hardcoded AI calls need systematic refactoring without breaking existing functionality - **This is the bedrock of the entire system**
2. **EnrichedContext Schema Design**: The JSON schema is the formal API between symbolic and neural layers - must be optimized for token efficiency and semantic richness
3. **"Symbolic Firewall" Implementation**: PDDL planner must successfully prevent logically impossible outputs while preserving narrative creativity
4. **Prompt Template Architecture**: Agent-specific templates must produce consistent, parseable outputs while maintaining narrative quality
5. **Performance & Cost Optimization**: Hierarchical pipeline must minimize API calls and token usage while maximizing context relevance

---

## 🏛️ Epic 0: World Ontology & Foundational Structure (The "Atlas")

**Goal:** Establish a robust and intelligent world model before building the agent. This solves the core problems of "entity explosion" and "flat, meaningless space."

**Current State:** 🟢 **90% Complete** - Strong ECS foundation with comprehensive hierarchical model, scale-aware positioning, agent tools, and security validation complete

*   **[x] Task 0.1: Enhance Hierarchical Spatial Model**
    *   **Objective:** Extend existing spatial hierarchy to support multi-scale roleplay scenarios from galactic exploration to slice-of-life interactions.
    *   **Current State:** ✅ `SpatialComponent` with sophisticated container/containable relationships already implemented
    *   **[x] Subtask 0.1.1: Add `ParentLink` Component for Explicit Hierarchies**
        *   [x] Create `ParentLink(entity_id)` component to provide explicit parent references alongside `SpatialComponent`
        *   [x] This enables queries like "What galaxy is this planet in?" or "What building is this office in?"
    *   **[x] Subtask 0.1.2: Define Spatial Scale Archetypes**
        *   [x] **Cosmic Scale**: Universe → Galaxy → System → World/Moon → Continent → Region
        *   [x] **Planetary Scale**: World → Continent → Country → City → District → Building → Room
        *   [x] **Intimate Scale**: Building → Floor → Room → Area → Furniture → Container
        *   [x] **Examples:**
            *   [x] **Star Wars Bounty Hunter**: `Universe(Star Wars) → Galaxy(Far Far Away) → System(Tatooine) → World(Tatooine) → Region(Mos Eisley) → Building(Cantina) → Room(Main Hall)`
            *   [x] **Office Worker**: `World(Earth) → Continent(North America) → Country(USA) → City(New York) → District(Manhattan) → Building(Corporate Tower) → Floor(42nd) → Room(Conference Room)`
            *   [x] **Galactic God**: Can move between any level: `Universe → Galaxy → System` etc.
    *   **[x] Subtask 0.1.3: Implement Scale-Aware Position System**
        *   [x] Enhanced `Position` component to work with hierarchical coordinates via `EnhancedPositionComponent`
        *   [x] Support both absolute coordinates (for gods/spaceships) and relative coordinates (for mortals) via `PositionType` enum
        *   [x] Example: Position(relative_to: "Tatooine Cantina", coordinates: (15.2, 8.5, 0.0))
        *   [x] Added `HierarchicalCoordinates` with scale awareness and metadata support
    *   **[x] Subtask 0.1.4: Write Multi-Scale Integration Tests**
        *   [x] Test cosmic hierarchy: Create "Star Wars Universe" → "Outer Rim" → "Tatooine System" → "Tatooine"
        *   [x] Test planetary hierarchy: Create "Earth" → "Europe" → "France" → "Paris" → "Apartment"
        *   [x] Test entity movement across scales: Player travels from "Tatooine" to "Coruscant" via "Hyperdrive"
        *   [x] Test scale-appropriate queries: "What's in this room?" vs "What systems are in this galaxy?"
    *   **[x] Subtask 0.1.5: Implement Dynamic Hierarchy Promotion (ENHANCEMENT)**
        *   [x] Created `promote_entity_hierarchy()` in `EcsEntityManager` for expanding scope when needed
        *   [x] Added recursive depth updating with `update_descendant_depths()` for hierarchy restructuring
        *   [x] Implemented hierarchy path traversal with `get_entity_hierarchy_path()` 
        *   [x] **Agent-Callable Tools**: Created `PromoteEntityHierarchyTool` and `GetEntityHierarchyTool` for AI systems
        *   [x] **JSON Interface**: Full JSON schema for agent interaction with hierarchy management
        *   [x] **Use Case**: When traveling between planets, automatically create solar system as new root entity
        *   [x] **Security Testing**: Comprehensive OWASP Top 10 security test suite (9 tests)
        *   [x] **Functional Testing**: Complete functional validation with edge cases (8 tests)
        *   [x] **Agent Integration**: Tools registered in agentic factory for AI agent access
    *   **[x] Subtask 0.1.6: Comprehensive Test Coverage (ENHANCEMENT)**
        *   [x] **Security Test Suite**: `hierarchy_tools_security_tests.rs` - 9 OWASP Top 10 compliant tests
            *   [x] A01 (Broken Access Control): Cross-user entity access prevention
            *   [x] A03 (Injection): SQL and JSON injection protection
            *   [x] A08 (Data Integrity): Input validation and data consistency
            *   [x] A09 (Logging/Monitoring): Security event logging validation
            *   [x] Business logic security: Depth limits, concurrent operations safety
        *   [x] **Functional Test Suite**: `hierarchy_tools_functional_tests.rs` - 8 comprehensive tests
            *   [x] Basic functionality: Entity promotion with parent creation
            *   [x] Complex scenarios: Star Wars interplanetary travel, office worker to cosmic god
            *   [x] Edge cases: Already promoted entities, root entity queries, nonexistent entities
        *   [x] **Integration Test Suites**: Multi-scale validation and position system tests
            *   [x] `multi_scale_integration_tests.rs`: Cross-scale hierarchy validation
            *   [x] `scale_aware_position_tests.rs`: Position system with hierarchical coordinates

*   **[ ] Task 0.2: Define and Implement Entity Salience Tiers**
    *   **Objective:** Differentiate between narratively critical entities and transient background details to prevent entity explosion across different scales.
    *   **Current State:** ❌ Not implemented - requires new component type
    *   **[ ] Subtask 0.2.1: Create Scale-Aware Salience Component**
        *   [ ] **`Salience` Component Enum:**
            *   [ ] **`Core`**: Player Characters, major NPCs, key locations (always tracked)
            *   [ ] **`Secondary`**: Supporting characters, important items, notable locations (tracked when relevant)
            *   [ ] **`Flavor`**: Scenery, background details, atmospheric elements (created/destroyed as needed)
        *   [ ] **Scale-Specific Examples:**
            *   [ ] **Galactic Scale**: Core = "Death Star", Secondary = "Imperial Fleet", Flavor = "Background starships"
            *   [ ] **Planetary Scale**: Core = "Tatooine", Secondary = "Mos Eisley", Flavor = "Random moisture farms"
            *   [ ] **Intimate Scale**: Core = "Player Character", Secondary = "Bartender", Flavor = "Cantina patrons"
    *   **[ ] Subtask 0.2.2: Implement Scale-Appropriate Entity Management**
        *   [ ] **Core entities**: Always exist, full component suite, persistent across sessions
        *   [ ] **Secondary entities**: Created when player enters relevant scale, simplified components
        *   [ ] **Flavor entities**: Generated on-demand, minimal components, garbage collected when out of scope
        *   [ ] **Examples:**
            *   [ ] God-level player: "Entire star systems" become Flavor entities until player focuses on them
            *   [ ] Office worker: "Other office buildings" are Flavor until player visits them
    *   **[ ] Subtask 0.2.3: Write Salience Management Tests**
        *   [ ] Test automatic salience promotion: Flavor → Secondary when player interacts
        *   [ ] Test salience demotion: Secondary → Flavor when player leaves area
        *   [ ] Test scale transitions: Office worker suddenly gains cosmic powers (salience rescaling)


*   [ ] Task 0.3: Make Foundational Tools AI-Driven
    *   **Objective:** Enhance the core "Atlas" tools with AI capabilities, moving beyond simple ECS wrappers to intelligent, context-aware operations. This addresses the need to make foundational tools AI-driven from the start, rather than only refactoring existing ones later.
    *   **Current State:** ❌ Not implemented - Existing tools are direct wrappers around ECS logic.
    *   **[ ] Subtask 0.3.1: Create AI-Powered Hierarchy Tools**
        *   [ ] **`AnalyzeHierarchyRequestTool`**: Create a new tool that uses Flash-Lite to interpret natural language requests (e.g., "show me the chain of command for this fleet") and translates them into formal queries for `GetEntityHierarchyTool`.
        *   [ ] **`SuggestHierarchyPromotionTool`**: Create a new tool that uses Flash to analyze narrative events and suggest when a hierarchy promotion is logical (e.g., "The characters have discussed the 'Crimson Fleet' extensively. Suggest promoting it to a `Core` salience entity with its own hierarchy.").
    *   **[ ] Subtask 0.3.2: Create AI-Powered Salience Management Tool**
        *   [ ] **`UpdateSalienceTool`**: Create a tool that uses Flash to analyze narrative context from a chat message or event and automatically assign or update an entity's `Salience` tier (`Core`, `Secondary`, `Flavor`).
        *   [ ] **Use Case**: When a background character ("a bartender") is mentioned repeatedly and becomes important to the plot, this tool would automatically promote them from `Flavor` to `Secondary` or `Core`.
    *   **[ ] Subtask 0.3.3: Write AI-Tool Integration Tests**
        *   [ ] Test `AnalyzeHierarchyRequestTool` with various natural language queries.
        *   [ ] Test `SuggestHierarchyPromotionTool` with narrative snippets that imply a promotion is needed.
        *   [ ] Test `UpdateSalienceTool` with before/after narrative contexts to verify correct salience assignment.
---

## ➡️ Epic 1: Foundational Refactoring & Decommissioning

**Goal:** Carefully dismantle the existing monolithic `EntityResolutionTool` and prepare the codebase for the new agentic framework, ensuring no valuable logic is lost.

**Current State:** 🔴 **Critical Flash Integration Required** - Extensive hardcoded AI functionality across multiple services needs refactoring

*   **[ ] Task 1.0: Comprehensive Flash Integration Refactoring (CRITICAL PRIORITY)**
    *   **Objective:** Fix the widespread architectural issue where multiple services bypass the Flash abstraction layer.
    *   **🚨 Critical Scope:** Analysis reveals 8+ services with hardcoded AI calls and system prompts
    *   **🎯 Architectural Vision:** This refactoring transforms scattered AI logic into a unified **Prompt Orchestration Engine** where Flash becomes the single, auditable interface to Gemini 2.5 Flash/Flash-Lite
    *   **[ ] Subtask 1.0.1: Core Agentic Tools (PRIORITY)**
        *   [ ] **`entity_resolution_tool.rs`**: Replace hardcoded context extraction and entity matching prompts with Flash-Lite
        *   [ ] **`agent_runner.rs`**: Replace hardcoded narrative analysis and triage prompts with Flash
        *   [ ] **`narrative_tools.rs`**: Replace hardcoded narrative triage prompts with Flash-Lite
    *   **[ ] Subtask 1.0.2: AI Analysis Services**
        *   [ ] **`intent_detection_service.rs`**: Replace hardcoded intent analysis prompts with Flash
        *   [ ] **`context_optimization_service.rs`**: Replace hardcoded context filtering prompts with Flash-Lite
        *   [ ] **`query_strategy_planner.rs`**: Replace hardcoded query planning prompts with Flash
    *   **[ ] Subtask 1.0.3: Character & Chat Generation**
        *   [ ] **`character_generation/field_generator.rs`**: Replace hardcoded character generation prompts with Flash
        *   [ ] **`chat/generation.rs`**: Replace hardcoded conversation generation with Flash integration
    *   **[ ] Subtask 1.0.4: Template & Prompt Framework**
        *   [ ] **`prompt_templates.rs`**: Convert hardcoded reasoning prompts to Flash template system
        *   [ ] **`prompt_builder.rs`**: Integrate Flash dynamic prompt construction
    *   **[ ] Subtask 1.0.5: Comprehensive Testing**
        *   [ ] Write integration tests for all Flash migrations
        *   [ ] Verify performance and cost optimization with Flash routing
        *   [ ] Ensure backward compatibility during transition
    *   **Priority:** CRITICAL - This architectural debt must be resolved before implementing hierarchical agents

*   **[ ] Task 1.1: Analyze and Deconstruct `EntityResolutionTool`**
    *   **Objective:** Map the logic from the existing tool to the new, decoupled toolkit.
    *   **Current State:** ✅ Multi-stage `EntityResolutionTool` exists with sophisticated logic that can be cleanly decomposed
    *   **🔴 Critical Issue Identified:** The existing tool uses hardcoded system prompts and manual AI client calls instead of Flash/Flash-Lite integration
    *   **[ ] Subtask 1.1.1:** Extract the core logic stages from `entity_resolution_tool.rs`:
        *   [ ] `extract_stage`: Rich narrative context extraction with `NarrativeContext` → **REFACTOR:** Replace hardcoded prompts with Flash-Lite integration, then migrate to `TacticalAgent`'s analysis capabilities
        *   [ ] `resolve_stage`: Semantic entity matching with vector similarity → migrate to new `find_entity` and `get_entity_details` tools
        *   [ ] `structure_stage`: Component suggestions and relationship identification → **REFACTOR:** Replace hardcoded analysis with Flash integration, then becomes core `TacticalAgent` reasoning
        *   [ ] `assemble_stage`: Final result packaging → replaced by `EnrichedContext` payload system
    *   **[ ] Subtask 1.1.2:** **PRIORITY:** Refactor hardcoded AI calls to use Flash/Flash-Lite before migration to preserve proper AI model abstraction
    *   **[ ] Subtask 1.1.3:** Mark `entity_resolution_tool.rs` and its tests as deprecated. Add comprehensive migration documentation pointing to this roadmap.

*   **[ ] Task 1.2: Clean Up Service Integration**
    *   **Objective:** Remove the old tool from the application's service registry.
    *   **Current State:** ✅ Clear service integration points identified in `factory.rs` and `mod.rs`
    *   **[ ] Subtask 1.2.1:** Remove `EntityResolutionTool` registration from `backend/src/services/agentic/factory.rs`.
    *   **[ ] Subtask 1.2.2:** Remove the re-export from `backend/src/services/agentic/mod.rs`.
    *   **[ ] Subtask 1.2.3:** Run `cargo check --all-targets` and fix any compilation errors. Note: Current system has good test coverage to catch regressions.

*   **[ ] Task 1.3: Convert Hardcoded Rule-Based Logic to AI-Driven Tools**
    *   **Objective:** Replace rigid, rule-based logic within agentic services with more flexible, context-aware AI calls. This is distinct from Task 1.0, which refactors existing *hardcoded AI calls*; this task focuses on converting *non-AI logic* (e.g., `match` statements, string formatting) into intelligent, AI-driven operations.
    *   **Current State:** ❌ Not implemented - Several key functions rely on simple string manipulation or hard-coded rules.
    *   **[ ] Subtask 1.3.1: Implement AI-Powered Chronicle Naming**
        *   **File:** `backend/src/services/agentic/agent_runner.rs`
        *   **Logic:** Replace the `generate_chronicle_name` function's string concatenation logic with a Flash call that generates a creative, summary-based name from the `ActionPlan`.
    *   **[ ] Subtask 1.3.2: Implement AI-Powered Entity Component Suggestion**
        *   **File:** `backend/src/services/agentic/entity_resolution_tool.rs`
        *   **Logic:** Replace the `suggest_components` function's hard-coded `match` statement with a Flash call that analyzes the `NarrativeContext` to suggest more relevant and specific components for an entity.
    *   **[ ] Subtask 1.3.3: Implement AI-Powered Lorebook Entry Merging**
        *   **File:** `backend/src/services/agentic/narrative_tools.rs`
        *   **Logic:** Implement the `UpdateLorebookEntryTool` with a Flash call that performs a "semantic merge" of new information with existing entry content, resolving contradictions and integrating data intelligently.
    *   **[ ] Subtask 1.3.4: Implement AI-Powered Semantic Entity Matching**
        *   **File:** `backend/src/services/agentic/entity_resolution_tool.rs`
        *   **Logic:** Enhance the `resolve_stage` to use a Flash call for semantic matching of entities, improving its ability to handle aliases, typos, and contextual references beyond simple string comparison.

---

## 🚀 Epic 2: Building the Tactical Toolkit (TDD & Security-First)

**Goal:** Implement the new, atomic world-interaction tools. These will serve as the primitive "actions" for the Planning Cortex.

**Current State:** 🟡 **60% Complete** - Core ECS operations exist but need atomic tool wrappers for agent consumption

*   **[ ] Task 2.1: Test and Implement `find_entity` and `get_entity_details`**
    *   **File:** `backend/src/services/agentic/tools/world_tools.rs` (new), `backend/tests/agentic/world_tools_tests.rs` (new)
    *   **Current State:** ✅ Entity search capabilities exist in `EcsEntityManager` and `EntityResolutionTool` - need atomic tool wrappers
    *   **[ ] Subtask 2.1.1: Write Tests First:**
        *   [ ] **Unit Test:** Mock DB/Vector stores. Test query construction for keyword and semantic search.
        *   [ ] **Integration Test:** Use existing `test_helpers` to create test entities. Assert the tool finds entities by exact name, alias, and semantic context.
        *   [ ] **Security Test (A03: Injection):** Test with malicious input (e.g., `' OR 1=1; --`) in `name` and `context` fields. Assert that the input is sanitized and not executed.
        *   [ ] **Security Test (A01: Broken Access Control):** Test that `get_entity_details` fails when a user attempts to access an entity they do not own.
    *   **[ ] Subtask 2.1.2: Implement `find_entity` and `get_entity_details`:** Wrap existing `EcsEntityManager` methods with agent-friendly interfaces.

*   **[ ] Task 2.2: Test and Implement `create_entity` and `update_entity`**
    *   **[ ] Subtask 2.2.1: Write Tests First:**
        *   [ ] **Integration Tests:** For `create_entity`, assert the entity and components (including `ParentLink` and `Salience`) are correctly created. For `update_entity`, assert component data is correctly modified.
        *   [ ] **Security Test (A08: Data Integrity):** For both tools, test with malformed JSON in the `components` payload. Assert the system rejects the request gracefully.
        *   [ ] **Security Test (A01: Broken Access Control):** For `update_entity`, test that a user cannot modify an entity they do not own.
    *   **[ ] Subtask 2.2.2: Implement `create_entity` and `update_entity`:** Write the implementation code.

*   **[ ] Task 2.3: Test and Implement Scale-Aware Spatial Tools**
    *   **Objective:** Give the agent the ability to manipulate and understand spatial relationships across different scales.
    *   **[ ] Subtask 2.3.1: Write Multi-Scale Movement Tests:**
        *   [ ] **`move_entity(entity_to_move, new_parent_entity)`:** Test moving entities across different scales:
            *   [ ] **Intimate Scale**: Move "Sol" from "Cantina Main Hall" to "Cantina Back Room"
            *   [ ] **Planetary Scale**: Move "Sol" from "Tatooine" to "Coruscant" (via hyperdrive)
            *   [ ] **Cosmic Scale**: Move "Imperial Fleet" from "Tatooine System" to "Alderaan System"
        *   [ ] **`get_contained_entities(parent_entity, scale_filter)`:** Test hierarchical queries:
            *   [ ] **Immediate Children**: "What's in this room?" (returns people, furniture, items)
            *   [ ] **Deep Hierarchy**: "What star systems are in this galaxy?" (returns all systems regardless of depth)
            *   [ ] **Scale-Filtered**: "What buildings are in this city?" (skips intermediate districts)
        *   [ ] **Security Test (A01):** Test that users cannot move entities they don't control, especially across scales
    *   **[ ] Subtask 2.3.2: Implement Scale-Aware Movement Logic**
        *   [ ] **`move_entity`** with scale validation (can't move planet into a room)
        *   [ ] **`get_contained_entities`** with depth and scale filtering
        *   [ ] **`get_movement_path`** to show valid movement routes between scales
        *   [ ] **`check_movement_constraints`** to validate movement rules (e.g., "needs spaceship to travel between systems")
    *   **[ ] Subtask 2.3.3: Implement Scale Transition Tools**
        *   [ ] **`zoom_in(entity, target_scale)`**: God-level player focuses on a star system, promoting its salience
        *   [ ] **`zoom_out(entity, target_scale)`**: Office worker sees city from space, demoting building details
        *   [ ] **`get_scale_context(entity)`**: Returns current scale and available movement options

*   **[ ] Task 2.4: Test and Implement Inventory & Relationship Tools**
    *   **Objective:** Provide specialized tools for common, high-impact interactions.
    *   **[ ] Subtask 2.4.1: Write Tests First:**
        *   [ ] **`add_item_to_inventory(character, item)`:** Test adding a "blaster" to "Sol's" `Inventory` component.
        *   [ ] **`remove_item_from_inventory(character, item)`:** Test the reverse operation.
        *   [ ] **`update_relationship(entity_a, entity_b, descriptor)`:** Test creating or updating a relationship in the `Relationships` component (e.g., `update_relationship("Sol", "Borga", "fears")`).
    *   **[ ] Subtask 2.4.2: Implement the inventory and relationship tools.**

---

## 🧠 Epic 3: The Planning & Reasoning Cortex (The "Blueprint") - 🔴 HIGH RISK

**Goal:** To create the "Blueprint" for the narrative by integrating a formal planner, providing a guarantee of causal consistency.

**Current State:** 🟡 **5% Complete** - Query planning infrastructure exists but no formal planning engine integration

**Risk Assessment:** 🔴 **HIGH RISK** - Complex integration with external planning frameworks that may not align cleanly with existing ECS architecture

*   **[ ] Task 3.1: Define the PDDL Action Domain**
    *   **Objective:** Translate the agent's toolkit from Epic 2 into a formal language the planner can understand.
    *   **Current State:** ❌ No formal planning language integration exists
    *   **Risk Mitigation:** Start with simple PDDL domain before attempting complex HTN integration
    *   **[ ] Subtask 3.1.1:** Create a `domain.pddl` file in `backend/resources/planning/`.
    *   **[ ] Subtask 3.1.2:** For each tool in `world_tools.rs` (e.g., `move_entity`), define a corresponding PDDL `(:action ...)` with `:parameters`, `:precondition`, and `:effect`. The predicates in the PDDL file must map directly to ECS components and relationships.

*   **[ ] Task 3.2: Integrate a Unified Planning Framework**
    *   **Objective:** Add a planning engine to the backend services.
    *   **Current State:** ❌ No formal planning framework integration
    *   **Risk Mitigation:** Research Rust-compatible planning frameworks before implementation
    *   **[ ] Subtask 3.2.1:** **RESEARCH PHASE:** Evaluate `AIPlan4EU Unified Planning Framework (UPF)` compatibility with Rust ecosystem. Consider alternatives like `planning-rs` or Python integration.
    *   **[ ] Subtask 3.2.2:** Create a new `backend/src/services/planning/mod.rs` module and a `PlanningService`.
    *   **[ ] Subtask 3.2.3:** Implement a `PlanningService::generate_plan` method that takes the current world state (as a structured representation of relevant ECS data) and a goal state, and uses the selected planning framework to generate a plan.
    *   **[ ] Subtask 3.2.4 (Security - A02):** The `generate_plan` method MUST require a `SessionDek` as an argument to decrypt the necessary world state data for planning. Add tests to confirm it fails without one.

*   **[ ] Task 3.3: Planner Integration Tests**
    *   **Objective:** Verify that the planner can generate a valid plan based on the world state.
    *   **File:** `backend/tests/planning_service_tests.rs` (new)
    *   **Current State:** ✅ Excellent test infrastructure exists with `test_helpers` - can be leveraged for planning tests
    *   **[ ] Subtask 3.3.1:** Write a test that:
        1.  [ ] Uses existing `test_helpers` to set up an initial world state in the test DB (e.g., "Sol is in the Chamber").
        2.  [ ] Defines a goal state as a set of predicates (e.g., "Sol is in the Cantina").
        3.  [ ] Calls the `PlanningService`.
        4.  [ ] Asserts that the service returns a non-empty, valid sequence of actions (e.g., `[move_entity("Sol", "Cantina")]`).
    *   **[ ] Subtask 3.3.2 (Security - A01):** Add a test case where the goal involves an entity not owned by the user, and assert that the planner fails to produce a plan, returning a `PermissionDenied` error.

---

## 🤖 Epic 4: Implementing the Tactical & Operational Layers (The "Puppet")

**Goal:** Build the agent that executes the planner's blueprint and integrate it into the application's request lifecycle.

*   **[ ] Task 4.1: Test and Implement the `TacticalAgent`**
    *   **File:** `backend/src/services/agentic/tactical_agent.rs` (new, replacing `pre_response_agent.rs`), `backend/tests/agentic/tactical_agent_tests.rs` (new)
    *   **Subtask 4.1.1: Write Reasoning Test First:**
        *   **Objective:** Verify the agent's decision-making process using the new planner.
        *   **Test:** Provide a narrative snippet: "Sol wants to go to the bustling cantina." Assert the agent calls the services in the correct sequence:
            1.  [ ] `PlanningService::generate_plan` with goal "Sol is in cantina".
            2.  [ ] Receives plan `[move_entity("Sol", "cantina")]`.
            3.  [ ] Identifies `move_entity` as the sub-goal to execute.
    *   **[ ] Subtask 4.1.2: Implement Agent Core Logic:**
        *   [ ] **Objective:** Write the agent's main loop and reasoning prompt.
        *   [ ] **Implementation:** Write the `TacticalAgent` struct and the master system prompt that instructs it to: receive a directive, get a plan from the `PlanningService`, and execute the *first step* of that plan by preparing an `EnrichedContext` payload for the `RoleplayAI` (the Operational Layer).
    *   **[ ] Subtask 4.1.3 (Security - A09):** Enhance logging to record the directive received, the full plan generated by the `PlanningCortex`, and the specific sub-goal chosen for execution.

*   **[ ] Task 4.2: Test and Implement Pipeline Integration**
    *   **File:** `backend/src/prompt_builder.rs`, `backend/src/services/chat/chat_service.rs`
    *   **[ ] Subtask 4.2.1: Write Integration Test First:**
        *   [ ] **Objective:** Verify the agent's output correctly enriches the final prompt.
        *   [ ] **Test:** Write a test that simulates a full request to the chat service. Invoke the `TacticalAgent`, capture the `EnrichedContext` it produces, and assert that this context is correctly passed to `prompt_builder.rs` and rendered into the final prompt string under the `<current_world_state>` tag.
    *   **[ ] Subtask 4.2.2: Implement the Integration:**
        *   [ ] **Objective:** Plumb the agent into the chat service.
        *   [ ] **Implementation:** Modify the chat service to call the `TacticalAgent`. Modify `prompt_builder.rs` to accept and render the `EnrichedContext`.
    *   **[ ] Subtask 4.2.3: Formalize the EnrichedContext Schema (CRITICAL)**
        *   [ ] **Define `EnrichedContext` as First-Class API**: Treat the JSON schema as the formal API between symbolic world and neural generation
        *   [ ] **Version the Schema**: Implement versioning to allow schema evolution without breaking changes
        *   [ ] **Document Schema Specification**: Create comprehensive documentation for the `EnrichedContext` structure
        *   [ ] **Implement Schema Validation**: Add runtime validation to ensure `TacticalAgent` produces valid payloads
        *   [ ] **Optimize for Token Efficiency**: Design schema to minimize token usage while maximizing context relevance

---

## ⚡ Epic 5: The Strategic Layer & Autonomic Loop (The "Autonomic System")

**Goal:** Develop the high-level "Director" and the parallel "Perception" agent, creating a fully autonomous, self-correcting system.

*   **[ ] Task 5.1: Test and Implement the `PerceptionAgent` (Foresight Engine)**
    *   **Objective:** Create the agent that processes the AI's response in the background, updating the world state for the next turn.
    *   **[ ] Subtask 5.1.1: Write Tests First:**
        *   [ ] **Unit Test:** Provide a mock AI response and assert the agent correctly identifies entities and state changes using its JERE model/extraction logic.
        *   [ ] **Integration Test:** In the main chat service test, after receiving a mock AI response, assert the `PerceptionAgent` is triggered in a background task (`tokio::spawn`) and correctly updates the database.
    *   **[ ] Subtask 5.1.2: Implement the `PerceptionAgent` and its asynchronous trigger in `chat_service.rs`.**

*   **[ ] Task 5.2: Implement Dynamic Re-planning**
    *   **Objective:** Enable the `TacticalAgent` to react to unexpected outcomes.
    *   **[ ] Subtask 5.2.1:** Modify the `TacticalAgent` to store the generated plan in a short-term cache.
    *   **[ ] Subtask 5.2.2:** On its next invocation, the `TacticalAgent` will first check if the world state (updated by the `PerceptionAgent`) matches the expected outcome of the last executed step.
    *   **[ ] Subtask 5.2.3:** If the state has deviated, the agent must invalidate the old plan and request a new one from the `PlanningService` based on the new reality.
    *   **[ ] Subtask 5.2.4:** Write integration tests for deviation scenarios (e.g., a "persuade" action fails) and assert that the agent correctly re-plans.

*   **[ ] Task 5.3: Implement the `StrategicAgent` (The "Director")**
    *   **Objective:** Create the high-level agent for long-term narrative management.
    *   **[ ] Subtask 5.3.1:** Create a new `StrategicAgent` service. Initially, it can be a simple pass-through that converts user intent into a goal for the `TacticalAgent`.
    *   **[ ] Subtask 5.3.2:** Develop a system prompt for the `StrategicAgent` that instructs it to analyze the overall chat history and define high-level narrative goals (e.g., "initiate combat," "introduce mystery," "resolve conflict").
    *   **[ ] Subtask 5.3.3:** Integrate the `StrategicAgent` into the `chat_service` so it runs before the `TacticalAgent`, providing the initial directive.
    *   **[ ] Subtask 5.3.4: Define Agent-Specific Prompt Templates (CRITICAL)**
        *   [ ] **StrategicAgent Prompt Template**: High-level prompt that receives chat history and world events, asks Gemini to "propose a narrative direction" like 'introduce mystery' or 'escalate conflict'
        *   [ ] **RoleplayAI Prompt Template**: Detailed prompt that receives rich `EnrichedContext` payload from `TacticalAgent` to generate final narrative output
        *   [ ] **Prompt Template Versioning**: Implement versioning system for prompt templates to enable A/B testing and iterative improvement
        *   [ ] **Template Validation**: Add validation to ensure prompt templates produce consistent, parseable outputs

---

## ✅ Epic 6: Full System Validation & Hardening

**Goal:** Verify the entire hierarchical pipeline works cohesively and is secure.

*   **[ ] Task 6.1: End-to-End Scenario Testing**
    *   **[ ] Subtask 6.1.1: Write Full Loop Test:** Write an integration test simulating a multi-turn conversation, asserting the world state in the database is correctly and consistently updated by the full `Strategic -> Tactical -> Perception` loop.
*   **[ ] Task 6.2: Security and Logging Validation**
    *   **[ ] Subtask 6.2.1: Security Review:**
        *   [ ] **A09: Logging Failures:** Review the full system to ensure all agent decisions, tool calls, and state changes are logged with sufficient detail for security auditing.
        *   [ ] **A05: Security Misconfiguration:** Ensure all new services and agents have appropriate, hardened configurations and do not expose unnecessary information in error messages.
    *   **[ ] Subtask 6.2.2: Manual QA:** Perform manual testing of the full flow to catch any issues not covered by automated tests.

---

## 🔐 **Security Framework for Hierarchical Agents**

**Current State:** ✅ **Excellent foundation** - Per-user encryption and access control architecture provides strong security base

### **Agent Security Requirements**

1. **[ ] Agent Authorization Framework**
   - [ ] Define security levels for Strategic, Tactical, and Operational layers
   - [ ] Implement agent capability restrictions based on user permissions
   - [ ] Add audit logging for high-privilege agent actions

2. **[ ] Planning Cortex Security**
   - [ ] Validate all planning inputs against user ownership
   - [ ] Implement plan execution limits and timeouts
   - [ ] Add security constraints to PDDL domain definitions

3. **[ ] Enhanced Security Monitoring**
   - [ ] Implement centralized security event correlation
   - [ ] Add automated alerting for suspicious agent activities
   - [ ] Create security dashboards for agent behavior monitoring

### **Security Integration Points**

- [ ] **SessionDek Integration**: All agents must operate with user-specific `SessionDek` for data decryption
- [ ] **Access Control**: Extend existing ownership-based filtering to agent operations
- [ ] **Audit Logging**: Log all agent decisions, tool calls, and state changes for security auditing
- [ ] **Error Handling**: Ensure agents don't expose sensitive information in error messages

### **Security Testing Strategy**

- [ ] **Agent Capability Testing**: Verify agents cannot exceed their authorized capabilities
- [ ] **Cross-User Isolation**: Test that agents cannot access data from other users
- [ ] **Input Validation**: Ensure all agent inputs are properly sanitized
- [ ] **Privilege Escalation**: Test that agents cannot escalate their privileges