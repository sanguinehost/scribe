# Sanguine Scribe: Living World Implementation Roadmap (V8 - Hierarchical Model)

**Vision:** To execute a methodical, test-driven migration to a **Hierarchical World Model**. This roadmap details the establishment of a rich world ontology (The Atlas), the integration of an AI-driven planning system (The Blueprint), the development of tactical and operational agents (The Puppet), and the creation of a strategic, autonomous narrative system (The Autonomic System), with security and testability as foundational pillars.

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
- **No Validated Planning**: The system lacks a dedicated planning-and-validation loop; agentic actions are generated without being explicitly validated against ECS ground truth before execution.
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

### **Phase 3: LLM Planning & Validation (6-8 weeks) - 🟡 MEDIUM RISK**
**Focus:** Add AI-driven planning with symbolic validation ("Symbolic Firewall")
- **Epics:** 3 (Planning Cortex)
- **Risk Level:** Medium - robust implementation of PlanValidator service required
- **Success Criteria:** LLM-generated plans validated against ECS ground truth before execution

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
3. **"Symbolic Firewall" Implementation**: The `PlanValidator` service must successfully prevent the execution of logically impossible or invalid actions proposed by the LLM, grounding the AI's creativity in the ECS's rules.
4. **Prompt Template Architecture**: Agent-specific templates must produce consistent, parseable outputs while maintaining narrative quality
5. **Performance & Cost Optimization**: Hierarchical pipeline must minimize API calls and token usage while maximizing context relevance

---

## 🏛️ Epic 0: World Ontology & Foundational Structure (The "Atlas")

**Goal:** Establish a robust and intelligent world model before building the agent. This solves the core problems of "entity explosion" and "flat, meaningless space."

**Current State:** 🟢 **100% Complete** - Comprehensive world ontology with hierarchical spatial model, entity salience tiers, and AI-powered foundational tools fully implemented

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

*   **[x] Task 0.2: Define and Implement Entity Salience Tiers**
    *   **Objective:** Differentiate between narratively critical entities and transient background details to prevent entity explosion across different scales.
    *   **Current State:** ✅ **COMPLETED** - Full implementation with comprehensive tests
    *   **[x] Subtask 0.2.1: Create Scale-Aware Salience Component**
        *   [x] **`Salience` Component Enum:**
            *   [x] **`Core`**: Player Characters, major NPCs, key locations (always tracked)
            *   [x] **`Secondary`**: Supporting characters, important items, notable locations (tracked when relevant)
            *   [x] **`Flavor`**: Scenery, background details, atmospheric elements (created/destroyed as needed)
        *   [x] **Scale-Specific Examples:**
            *   [x] **Galactic Scale**: Core = "Death Star", Secondary = "Imperial Fleet", Flavor = "Background starships"
            *   [x] **Planetary Scale**: Core = "Tatooine", Secondary = "Mos Eisley", Flavor = "Random moisture farms"
            *   [x] **Intimate Scale**: Core = "Player Character", Secondary = "Bartender", Flavor = "Cantina patrons"
        *   [x] **Implementation Details:**
            *   [x] Created `SalienceTier` enum with Core/Secondary/Flavor variants
            *   [x] Implemented `SalienceComponent` with full lifecycle management
            *   [x] Added promotion/demotion tracking with interaction counting
            *   [x] Integrated scale-appropriate assignment with `SpatialScale` awareness
            *   [x] Created `SalienceExamples` for different scales with automatic assignment logic
    *   **[x] Subtask 0.2.2: Implement Scale-Appropriate Entity Management**
        *   [x] **Core entities**: Always exist, full component suite, persistent across sessions
        *   [x] **Secondary entities**: Created when player enters relevant scale, simplified components
        *   [x] **Flavor entities**: Generated on-demand, minimal components, garbage collected when out of scope
        *   [x] **Examples:**
            *   [x] God-level player: "Entire star systems" become Flavor entities until player focuses on them
            *   [x] Office worker: "Other office buildings" are Flavor until player visits them
        *   [x] **Implementation Details:**
            *   [x] Added `create_entity_with_salience()` for automatic salience assignment
            *   [x] Implemented `update_entity_salience()` for tier transitions
            *   [x] Created `promote_entity_salience()` and `demote_entity_salience()` with interaction tracking
            *   [x] Added `find_garbage_collectible_entities()` and `garbage_collect_entities()` for Flavor cleanup
            *   [x] Implemented `record_entity_interaction()` for automatic salience tracking
            *   [x] Added `get_entities_by_salience()` for tier-specific queries
            *   [x] Created component simplification logic for different salience tiers
    *   **[x] Subtask 0.2.3: Write Salience Management Tests**
        *   [x] Test automatic salience promotion: Flavor → Secondary when player interacts
        *   [x] Test salience demotion: Secondary → Flavor when player leaves area
        *   [x] Test scale transitions: Office worker suddenly gains cosmic powers (salience rescaling)
        *   [x] **Comprehensive Test Suite (15 tests):**
            *   [x] Salience component creation, serialization, promotion/demotion
            *   [x] Scale-appropriate salience assignment and validation
            *   [x] Interaction tracking and threshold-based promotion
            *   [x] Garbage collection eligibility and component simplification
            *   [x] Examples validation for Cosmic/Planetary/Intimate scales


*   **[x] Task 0.3: Make Foundational Tools AI-Driven**
    *   **Objective:** Enhance the core "Atlas" tools with AI capabilities, moving beyond simple ECS wrappers to intelligent, context-aware operations. This addresses the need to make foundational tools AI-driven from the start, rather than only refactoring existing ones later.
    *   **Current State:** ✅ **COMPLETED** - Full implementation with comprehensive AI-powered tools and testing infrastructure
    *   **[x] Subtask 0.3.1: Create AI-Powered Hierarchy Tools**
        *   [x] **`AnalyzeHierarchyRequestTool`**: Create a new tool that uses Flash-Lite to interpret natural language requests (e.g., "show me the chain of command for this fleet") and translates them into formal queries for `GetEntityHierarchyTool`.
        *   [x] **`SuggestHierarchyPromotionTool`**: Create a new tool that uses Flash to analyze narrative events and suggest when a hierarchy promotion is logical (e.g., "The characters have discussed the 'Crimson Fleet' extensively. Suggest promoting it to a `Core` salience entity with its own hierarchy.").
        *   [x] **Implementation Details:**
            *   [x] Created `AnalyzeHierarchyRequestTool` with sophisticated natural language interpretation using Flash-Lite (gemini-2.5-flash-lite-preview-06-17)
            *   [x] Implemented `SuggestHierarchyPromotionTool` with narrative analysis using Flash (gemini-2.5-flash-preview-06-17)
            *   [x] Both tools integrated with existing `GetEntityHierarchyTool` for seamless hierarchy operations
            *   [x] Registered in agentic factory for AI agent access
    *   **[x] Subtask 0.3.2: Create AI-Powered Salience Management Tool**
        *   [x] **`UpdateSalienceTool`**: Create a tool that uses Flash to analyze narrative context from a chat message or event and automatically assign or update an entity's `Salience` tier (`Core`, `Secondary`, `Flavor`).
        *   [x] **Use Case**: When a background character ("a bartender") is mentioned repeatedly and becomes important to the plot, this tool would automatically promote them from `Flavor` to `Secondary` or `Core`.
        *   [x] **Implementation Details:**
            *   [x] Created sophisticated AI-driven salience analysis using Flash (gemini-2.5-flash-preview-06-17)
            *   [x] Integrated with existing `SalienceTier` and `SpatialScale` enums for seamless ECS integration
            *   [x] Supports all salience tier transitions with confidence scoring and reasoning
            *   [x] Context-aware analysis for different scales (Cosmic/Planetary/Intimate)
    *   **[x] Subtask 0.3.3: Write AI-Tool Integration Tests**
        *   [x] Test `AnalyzeHierarchyRequestTool` with various natural language queries.
        *   [x] Test `SuggestHierarchyPromotionTool` with narrative snippets that imply a promotion is needed.
        *   [x] Test `UpdateSalienceTool` with before/after narrative contexts to verify correct salience assignment.
        *   [x] **Comprehensive Test Suite (11 tests):**
            *   [x] Basic functionality tests for all three AI tools
            *   [x] Error handling and invalid input tests
            *   [x] Comprehensive workflow integration testing
            *   [x] Multi-scale scenario validation (Cosmic/Planetary/Intimate)
            *   [x] Edge case handling (no promotions, flavor scenery, cosmic entities)
        *   [x] **Centralized Testing Infrastructure:**
            *   [x] Created `ai_tool_testing` module in `test_helpers.rs` with reusable test infrastructure
            *   [x] Implemented `ToolTestConfig`, `ToolTestSetup` for standardized tool testing
            *   [x] Added helper functions for tool creation, mock AI configuration, and result validation
            *   [x] Designed for scalability to support dozens of future AI tools
---

## ➡️ Epic 1: Foundational Refactoring & Decommissioning

**Goal:** Carefully dismantle the existing monolithic `EntityResolutionTool` and prepare the codebase for the new agentic framework, ensuring no valuable logic is lost.

**Current State:** ✅ **EPIC 1 COMPLETED** - All Flash integration and AI-driven logic conversion tasks complete

*   **[x] Task 1.0: Comprehensive Flash Integration Refactoring (CRITICAL PRIORITY)** ✅ **COMPLETED (2025-07-13)**
    *   **Objective:** Fix the widespread architectural issue where multiple services bypass the Flash abstraction layer.
    *   **🚨 Critical Scope:** Analysis reveals 8+ services with hardcoded AI calls and system prompts
    *   **🎯 Architectural Vision:** This refactoring transforms scattered AI logic into a unified **Prompt Orchestration Engine** where Flash becomes the single, auditable interface to Gemini 2.5 Flash/Flash-Lite
    *   **✅ PROGRESS UPDATE (2025-07-12):** Subtask 1.0.1 fully completed - Core agentic tools now use Flash/Flash-Lite throughout
    *   **[x] Subtask 1.0.1: Core Agentic Tools (PRIORITY) ✅ COMPLETED**
        *   [x] **`entity_resolution_tool.rs`**: Replace hardcoded context extraction and entity matching prompts with Flash-Lite
        *   [x] **`agent_runner.rs`**: Replace hardcoded narrative analysis and triage prompts with Flash
        *   [x] **`narrative_tools.rs`**: Replace hardcoded narrative triage prompts with Flash-Lite ✅
            *   [x] **Narrative Intelligence Service**: Main orchestrator implementing 4-step agentic workflow
                *   Triage → Flash-Lite determines narrative significance
                *   Retrieve → Context assembly with Flash-enhanced queries
                *   Plan → Flash generates action plans for world state updates
                *   Execute → Coordinated tool execution with Flash validation
            *   [x] **Flash-Powered Tools**: All 7 narrative tools now use Flash/Flash-Lite
                *   `AnalyzeTextSignificanceTool` - Flash-Lite powered significance analysis
                *   `CreateChronicleEventTool` - Flash-powered event creation
                *   `CreateLorebookEntryTool` - Flash-powered lorebook entry creation
                *   `ExtractTemporalEventsTool` - Flash-powered temporal extraction
                *   `ExtractWorldConceptsTool` - Flash-powered concept extraction
                *   `SearchKnowledgeBaseTool` - Flash-powered knowledge search
                *   `UpdateLorebookEntryTool` - Flash-powered entry updates
            *   [x] **Security Tests**: Comprehensive OWASP Top 10 test coverage added
                *   `agent_runner_security_tests.rs` - Access control, injection protection
                *   `entity_resolution_security_tests.rs` - Entity isolation, data integrity
                *   `narrative_tools_security_tests.rs` - Tool-specific security validation
            *   [x] **Integration Tests**: Smoke tests verify Flash integration works correctly
                *   `flash_integration_smoke_test.rs` - Verifies all components instantiate and configure properly
    *   **[x] Subtask 1.0.2: AI Analysis Services** ✅ COMPLETED (2025-07-13)
        *   [x] **`intent_detection_service.rs`**: Replace hardcoded intent analysis prompts with Flash ✅
            *   [x] Implemented Flash-Lite for structured intent detection (7 intent types)
            *   [x] Implemented Flash for narrative intent analysis
            *   [x] Created 12 functional tests covering all intent types
            *   [x] Created 12 OWASP Top 10 security tests
            *   [x] Fixed security vulnerability: Added confidence value validation (.clamp)
        *   [x] **`context_optimization_service.rs`**: Replace hardcoded context filtering prompts with Flash-Lite ✅
            *   [x] Implemented Flash-Lite for AI-driven context optimization
            *   [x] Added `optimize_for_narrative` method with Flash integration
            *   [x] Introduced new AI strategies: NarrativeCoherence, EmotionalResonance, ActionPotential
            *   [x] Created 11 functional tests covering all optimization strategies
            *   [x] Created 12 OWASP Top 10 security tests
            *   [x] Fixed security issues: Added validation for all score values
            *   [x] Added compatibility method for existing code integration
        *   [x] **`query_strategy_planner.rs`**: Replace hardcoded query planning prompts with Flash ✅
            *   [x] Implemented Flash integration for AI-driven query strategy planning
            *   [x] Added `create_adaptive_strategy` method with sophisticated Flash-powered analysis
            *   [x] Created 11 functional tests covering all strategy types and edge cases
            *   [x] Created 10 OWASP Top 10 security tests covering all vulnerability categories
            *   [x] Maintained backward compatibility with legacy `plan_queries` method
        *   [x] **`context_assembly_engine.rs`**: Refactor to create `EnrichedContext` payloads (COMPLETED) ✅
            *   [x] **Complete Living World Architecture Implementation**: Transformed from reactive `AssembledContext` to proactive `EnrichedContext`
            *   [x] **Hierarchical Agent Framework Integration**: Full support for Strategic, Tactical, and Operational layers
            *   [x] **Flash AI Integration**: Primary `enrich_context()` method using Flash for complex planning and Flash-Lite for extraction
            *   [x] **EnrichedContext Structure**: Complete implementation with strategic directives, validated plans, sub-goals, entity context, and symbolic firewall checks
            *   [x] **Backward Compatibility**: Legacy `execute_plan()` method maintained for existing code integration
            *   [x] **Comprehensive Testing**: 11 functional tests and 10 OWASP Top 10 security tests
    *   **[x] Subtask 1.0.3: Character Generation Flash Integration**
        *   [x] **`character_generation/field_generator.rs`**: ✅ **COMPLETED** - Successfully integrated Flash-Lite (`config.agentic_extraction_model`) for structured character field generation with comprehensive OWASP Top 10 security tests
            *   [x] **Flash-Lite Integration**: Updated model selection from hardcoded `token_counter_default_model` to `agentic_extraction_model` at lines 105 and 853
            *   [x] **Two Main Flows Documented**: UI-based field generation (CharacterCreator.svelte, CharacterEditor.svelte) and agentic character card production foundation
            *   [x] **Comprehensive Security Testing**: Full OWASP Top 10 test suite covering authentication, injection protection, access control, data integrity, and more
            *   [x] **Integration Testing**: Real AI integration tests, lorebook context integration, and validation edge cases
        *   **`chat/generation.rs`**: ✅ **SKIP** - Already properly architected with session-configurable models and sophisticated AI client integration. This service serves as the **Operational Layer** endpoint for hierarchical agents and requires no Flash integration - future `TacticalAgent` will provide `EnrichedContext` payloads to the existing, unchanged generation service.
    *   **[x] Subtask 1.0.4: EnrichedContext Prompt Builder Integration** ✅ **COMPLETED (2025-07-13)**
        *   [x] **`prompt_builder.rs`**: Evolve from character-only prompts to support full `EnrichedContext` payloads from hierarchical agents ✅
            *   [x] **EnrichedContext Integration**: Modified prompt builder to accept and format `EnrichedContext` objects (strategic directives, validated plans, sub-goals, entity context) ✅
            *   [x] **Flash-Optimized Templates**: Created structured prompt templates specifically designed for Flash/Flash-Lite with complex hierarchical context ✅
            *   [x] **Backward Compatibility**: Maintained existing character/RAG prompt functionality while adding hierarchical context support ✅
            *   [x] **Performance Metrics**: Added performance tracking integration (total_tokens_used, execution_time_ms, confidence_score) ✅
            *   [x] **Comprehensive Testing**: Created 10 functional tests and 6 OWASP Top 10 security tests, all passing ✅
            *   [x] **Hierarchical Context Assembly**: Build prompts that incorporate Director directives ✅ **COMPLETED (2025-07-13)**
                * [x] Implemented HierarchicalContextAssembler service as bridge solution
                * [x] Added Flash-powered strategic analysis and tactical planning
                * [x] Proper encryption with user_dek throughout the service
                * [x] Created comprehensive functional and OWASP security tests (21 tests total)
                * [x] Integrated into chat route pipeline with graceful fallback
                * [x] Added circular dependency handling (Optional field, post-construction initialization)
                * [x] Implemented to_prompt_string() method for debugging and development
                * [x] All tests passing: 9 functional + 12 OWASP Top 10 security tests
                * [x] Production-ready with comprehensive security validation
                * [x] **Note**: Symbolic Firewall integration will be implemented in Epic 3 (Planning & Reasoning Cortex)
        *   [x] **Context Orchestration**: Transform prompt builder into sophisticated "EnrichedContext Orchestrator" for future hierarchical agent system ✅ **COMPLETED (2025-07-13)**
            * [x] **Prompt Mode Intelligence**: Implemented PromptMode enum (Legacy, Enriched, Hybrid) with intelligent routing
            * [x] **Flash Optimization**: Flash/Flash-Lite routing based on context complexity and model capabilities
            * [x] **Template Management**: Sophisticated section builders for strategic directives, tactical plans, entity context, spatial/temporal context
            * [x] **Performance Integration**: Added token counting, execution time tracking, and confidence scoring
            * [x] **Comprehensive Testing**: 10 functional tests covering all prompt modes and context types
    *   **[x] Subtask 1.0.5: Comprehensive Testing** ✅ **COMPLETED (2025-07-13)**
        *   [x] Write integration tests for all Flash migrations
        *   [x] Verify performance and cost optimization with Flash routing
        *   [x] Ensure backward compatibility during transition
    *   **Priority:** CRITICAL - This architectural debt must be resolved before implementing hierarchical agents

*   **[x] Task 1.1: Analyze and Deconstruct `EntityResolutionTool`** ✅ **COMPLETED**
    *   **Objective:** Map the logic from the existing tool to the new, decoupled toolkit.
    *   **Current State:** ✅ Multi-stage `EntityResolutionTool` exists with sophisticated logic that can be cleanly decomposed
    *   **✅ Analysis Complete:** EntityResolutionTool is already entirely AI-powered with Flash/Flash-Lite integration
    *   **[x] Subtask 1.1.1:** ✅ **ANALYSIS COMPLETE** - Core logic stages already properly implemented:
        *   [x] `extract_stage`: Uses Flash-Lite for narrative context extraction with `NarrativeContext` (lines 294-319, 357-375)
        *   [x] `resolve_stage`: Uses `AiSemanticMatcher` for intelligent entity matching, not hardcoded string comparison (lines 377-447)
        *   [x] `structure_stage`: Uses `AiComponentSuggester` for intelligent component suggestions based on narrative context (lines 449-499)
        *   [x] `assemble_stage`: Properly packages results with processing metadata (lines 500+)
    *   **[x] Subtask 1.1.2:** ✅ **VERIFIED** - All AI calls properly use Flash/Flash-Lite abstraction layer (no hardcoded prompts/models)
    *   **[x] Subtask 1.1.3:** ✅ **CONFIRMED** - Tool is already properly structured with comprehensive AI-driven logic, no deprecation needed

*   **[x] Task 1.2: Clean Up Service Integration** ✅ **CANCELLED - TOOL SHOULD REMAIN**
    *   **Objective:** ~~Remove the old tool from the application's service registry~~ → **CANCELLED: Tool is properly implemented and should remain**
    *   **Current State:** ✅ EntityResolutionTool is properly implemented with Flash integration and should remain registered
    *   **[x] Subtask 1.2.1:** ✅ **CANCELLED** - EntityResolutionTool registration should remain in `factory.rs` (lines 152-153, 223-224)
    *   **[x] Subtask 1.2.2:** ✅ **CANCELLED** - Re-export should remain in `mod.rs` (lines 19, 36) as tool is properly implemented
    *   **[x] Subtask 1.2.3:** ✅ **NOT NEEDED** - No changes required as tool is working correctly

*   **[x] Task 1.3: Convert Hardcoded Rule-Based Logic to AI-Driven Tools** ✅ **COMPLETED**
    *   **Objective:** Replace rigid, rule-based logic within agentic services with more flexible, context-aware AI calls. This is distinct from Task 1.0, which refactors existing *hardcoded AI calls*; this task focuses on converting *non-AI logic* (e.g., `match` statements, string formatting) into intelligent, AI-driven operations.
    *   **🎯 Key Principle:** Let Flash/Flash-Lite make intelligent decisions based on context, rather than following predetermined rules. The AI should analyze, reason, and suggest - not just extract data.
    *   **Current State:** ✅ **FULLY IMPLEMENTED** - Task 1.1 analysis confirmed all AI-driven logic implementations are complete
    *   **[x] Subtask 1.3.1: Implement AI-Powered Chronicle Naming** ✅ **COMPLETED**
        *   **File:** `backend/src/services/agentic/agent_runner.rs`
        *   **Logic:** ✅ Implemented `generate_ai_chronicle_name()` with Flash-powered creative naming based on triage results, replacing string concatenation
    *   **[x] Subtask 1.3.2: Implement AI-Powered Entity Component Suggestion** ✅ **COMPLETED**
        *   **File:** `backend/src/services/agentic/entity_resolution_tool.rs`
        *   **Implementation:** ✅ `structure_stage_with_ai()` uses `component_suggester.suggest_components()` with full narrative context for intelligent component suggestions
    *   **[x] Subtask 1.3.3: Implement AI-Powered Lorebook Entry Merging** ✅ **COMPLETED**
        *   **File:** `backend/src/services/agentic/narrative_tools.rs`
        *   **Implementation:** ✅ `UpdateLorebookEntryTool` has Flash-powered semantic merging with conflict resolution and intelligent data integration
    *   **[x] Subtask 1.3.4: Implement AI-Powered Semantic Entity Matching** ✅ **COMPLETED**
        *   **File:** `backend/src/services/agentic/entity_resolution_tool.rs`
        *   **Implementation:** ✅ Uses `AiSemanticMatcher` with `find_semantic_match()` for context-aware entity matching, replacing simple string comparison

---

## 🚀 Epic 2: Building the Tactical Toolkit (TDD & Security-First)

**Goal:** Implement the new, atomic world-interaction tools. These will serve as the primitive "actions" for the Planning Cortex.

**Current State:** 🟢 **100% Complete** - Core ECS operations, comprehensive spatial tools, and inventory & relationship tools fully implemented

*   **[x] Task 2.1: Test and Implement `find_entity` and `get_entity_details`** ✅ **COMPLETED (2025-07-13)**
    *   **File:** `backend/src/services/agentic/tools/world_interaction_tools.rs`, `backend/tests/world_interaction_tools_tests.rs`, `backend/tests/world_interaction_tools_security_tests.rs`
    *   **Current State:** ✅ **FULLY IMPLEMENTED** - Atomic world-interaction tools for the Planning Cortex with comprehensive testing
    *   **[x] Subtask 2.1.1: Write Tests First:** ✅ **COMPLETED**
        *   [x] **Functional Tests (9 tests):** Complete test coverage including entity search by name/scale/parent/component, entity details with hierarchy/relationships, and error handling
        *   [x] **Security Tests (19 tests):** Comprehensive OWASP Top 10 security test suite covering all vulnerability categories:
            *   [x] **A01 (Broken Access Control):** User isolation, privilege escalation prevention (3 tests)
            *   [x] **A03 (Injection):** SQL, NoSQL, and JSON injection protection (3 tests)
            *   [x] **A04 (Insecure Design):** Rate limiting, information disclosure prevention (2 tests)
            *   [x] **A05 (Security Misconfiguration):** Input validation, schema enforcement (3 tests)
            *   [x] **A07 (Authentication Failures):** User ID validation, session context integrity (2 tests)
            *   [x] **A08 (Data Integrity):** Data consistency, malformed data handling (2 tests)
            *   [x] **A09 (Logging/Monitoring):** Security event logging, audit trails (2 tests)
            *   [x] **A10 (SSRF):** External request prevention, internal network access blocking (2 tests)
    *   **[x] Subtask 2.1.2: Implement `find_entity` and `get_entity_details`:** ✅ **COMPLETED**
        *   [x] **FindEntityTool:** Comprehensive entity search supporting name, scale, parent, component, and advanced queries
        *   [x] **GetEntityDetailsTool:** Detailed entity inspection with optional hierarchy and relationship information
        *   [x] **Agent Integration:** Tools registered in agentic factory for AI agent access with JSON schema validation
        *   [x] **Error Handling:** Comprehensive error handling with ToolError enum and proper user isolation
        *   [x] **Performance:** Query limits enforced (max 100 results) to prevent resource exhaustion

*   **[x] Task 2.2: Test and Implement `create_entity` and `update_entity`** ✅ **COMPLETED**
    *   **[x] Subtask 2.2.1: Write Tests First:**
        *   [x] **Functional Tests:** Created 7 comprehensive tests covering basic creation, parent/salience support, updates, component operations
        *   [x] **Security Tests:** Implemented 17 OWASP-based security tests covering all Top 10 categories
        *   [x] **Critical Bug Found:** Discovered SQL injection vulnerability in EcsEntityManager's `ComponentDataMatches` query
    *   **[x] Subtask 2.2.2: Implement `create_entity` and `update_entity`:**
        *   [x] **CreateEntityTool:** Full entity creation with parent links, salience tiers, and component validation
        *   [x] **UpdateEntityTool:** Component updates supporting Add/Update/Remove operations with ownership checks
        *   [x] **Validation:** Component type and schema validation to prevent invalid data
        *   [x] **Agent Integration:** Both tools registered in agentic factory with JSON schemas

*   **[x] Task 2.3: Test and Implement Scale-Aware Spatial Tools** ✅ **COMPLETED (2025-07-13)**
    *   **Objective:** Give the agent the ability to manipulate and understand spatial relationships across different scales.
    *   **✅ CRITICAL GAP RESOLVED:** Implemented comprehensive spatial tools including both upward traversal (ancestors) and downward traversal (descendants/children) for complete hierarchical spatial queries.
    *   **[x] Subtask 2.3.1: Write Spatial Hierarchy Query Tests:** ✅ **COMPLETED**
        *   [x] **`get_contained_entities(parent_entity, options)`:** Implemented comprehensive hierarchical downward queries:
            *   [x] **Immediate Children Only**: "What's directly in this room?" (depth=1)
            *   [x] **All Descendants**: "What entities exist on planet Tatooine?" (depth=unlimited, includes cities, buildings, rooms, characters, items)
            *   [x] **Scale-Filtered Descendants**: "What star systems are in this galaxy?" (depth=unlimited, scale_filter="System")
            *   [x] **Combined Filters**: "What characters are on this planet?" (depth=unlimited, component_filter="Character")
        *   [x] **Enhanced spatial queries:**
            *   [x] **Recursive Search**: Find all entities within a galaxy/system/planet regardless of hierarchy depth
            *   [x] **Scale-Aware Results**: Return results organized by scale (Systems → Planets → Cities → etc.)
            *   [x] **Performance Tests**: Verified queries scale well with deep hierarchies (tested with complex multi-scale scenarios)
        *   [x] **Integration with Existing Tools**:
            *   [x] Enhanced compatibility with existing `ParentLink` and `SpatialArchetype` components
            *   [x] Comprehensive test coverage: 14 functional tests + 14 OWASP Top 10 security tests
    *   **[x] Subtask 2.3.2: Implement Core Spatial Query Methods in EcsEntityManager** ✅ **COMPLETED**
        *   [x] **`get_children_entities(parent_id, limit)`**: Direct children queries with user isolation
        *   [x] **`get_descendants_entities(parent_id, max_depth, limit)`**: Breadth-first hierarchical traversal with depth limits
        *   [x] **Performance Optimizations**: 
            *   [x] Implemented Redis caching for frequently accessed hierarchies with user-specific cache keys
            *   [x] Optimized database queries with proper indexing support
            *   [x] Breadth-first search algorithm for efficient deep hierarchy traversal
    *   **[x] Subtask 2.3.3: Implement Agent-Accessible Spatial Query Tools** ✅ **COMPLETED**
        *   [x] **`GetContainedEntitiesTool`**: Comprehensive spatial query wrapper with depth control and filtering
        *   [x] **`GetSpatialContextTool`**: Returns both ancestors and descendants for complete spatial context
        *   [x] **Agent Integration**: Both tools registered in agentic factory with full JSON schema validation
    *   **[x] Subtask 2.3.4: Implement Movement and Scale Transition Tools** ✅ **COMPLETED**
        *   [x] **`move_entity(entity_to_move, new_parent_entity)`:** Comprehensive movement system across different scales:
            *   [x] **Intimate Scale**: Move entities between rooms and buildings
            *   [x] **Planetary Scale**: Move entities between planets and systems
            *   [x] **Cosmic Scale**: Move fleets and entities across star systems
        *   [x] **`MoveEntityTool`** with comprehensive validation:
            *   [x] Scale compatibility validation (can't move planet into a room)
            *   [x] Circular parent relationship prevention
            *   [x] User ownership validation and access control
            *   [x] Position update support with HTML sanitization for security
        *   [x] **Security Implementation**:
            *   [x] OWASP Top 10 compliance with 14 comprehensive security tests
            *   [x] Script injection prevention with HTML content sanitization
            *   [x] Multi-tenant user isolation with proper access controls
            *   [x] Transaction integrity with proper rollback support
        *   [x] **Test Coverage**:
            *   [x] 10 functional movement tests covering all scales and edge cases
            *   [x] 14 OWASP Top 10 security tests covering all attack vectors
            *   [x] Cache performance and transaction integrity validation

*   **[x] Task 2.4: Test and Implement Inventory & Relationship Tools** ✅ **COMPLETED (2025-07-13)**
    *   **Objective:** Provide specialized tools for common, high-impact interactions.
    *   **File:** `backend/src/services/agentic/tools/world_interaction_tools.rs`, `backend/tests/world_interaction_tools_inventory_tests.rs`, `backend/tests/world_interaction_tools_relationship_tests.rs`, `backend/tests/world_interaction_tools_inventory_relationship_security_tests.rs`
    *   **Current State:** ✅ **FULLY IMPLEMENTED** - Inventory and relationship tools with comprehensive testing and OWASP Top 10 security compliance
    *   **[x] Subtask 2.4.1: Write Tests First:** ✅ **COMPLETED**
        *   [x] **Functional Tests (18 tests):** Complete test coverage for inventory operations (9 tests) and relationship management (9 tests)
        *   [x] **Security Tests (21 tests):** Comprehensive OWASP Top 10 security test suite covering all vulnerability categories:
            *   [x] **A01 (Broken Access Control):** Cross-user access prevention (3 tests)
            *   [x] **A02 (Cryptographic Failures):** Data integrity validation (2 tests)
            *   [x] **A03 (Injection):** SQL, NoSQL, and JSON injection protection (3 tests)
            *   [x] **A04 (Insecure Design):** Business logic validation (2 tests)
            *   [x] **A05 (Security Misconfiguration):** Input validation and schema enforcement (3 tests)
            *   [x] **A07 (Authentication Failures):** User ID and session validation (2 tests)
            *   [x] **A08 (Data Integrity):** Data consistency and malformed data handling (2 tests)
            *   [x] **A09 (Logging/Monitoring):** Security event logging validation (2 tests)
            *   [x] **A10 (SSRF):** SSRF prevention validation (2 tests)
    *   **[x] Subtask 2.4.2: Implement the inventory and relationship tools.** ✅ **COMPLETED**
        *   [x] **EcsEntityManager Methods (4 methods):**
            *   [x] `add_item_to_inventory()`: Handles capacity checking, quantity stacking, and slot assignment
            *   [x] `remove_item_from_inventory()`: Handles quantity validation and item removal
            *   [x] `update_relationship()`: Creates/updates relationships with trust/affection bounds validation
            *   [x] `get_relationships()`: Retrieves all relationships for an entity
        *   [x] **Agent-Accessible Tools (3 tools):**
            *   [x] `AddItemToInventoryTool`: Comprehensive inventory addition with validation
            *   [x] `RemoveItemFromInventoryTool`: Safe item removal with quantity checks
            *   [x] `UpdateRelationshipTool`: Relationship management with metadata support
        *   [x] **Agent Integration:** All tools registered in agentic factory with JSON schema validation
        *   [x] **Security Implementation:** Multi-tenant user isolation, access control, and cache invalidation
        *   [x] **Performance Features:** Redis caching, transaction integrity, and proper error handling

---

## 🧠 Epic 3: The Planning & Reasoning Cortex (The "Blueprint") - 🟡 MEDIUM RISK

**Goal:** To create the "Blueprint" for the narrative by implementing an **LLM-as-a-Planner**. This system uses a sophisticated, AI-driven prompt construction process to generate a sequence of actions as a structured JSON object. This plan is then rigorously validated against the ECS ground truth by a "Symbolic Firewall" before execution, ensuring causal consistency without the rigidity of an external formal planning engine.

**Current State:** 🟢 **75% Complete** - Action Schema, Planning Types, LLM-based Planning Service, and Plan Validator (Symbolic Firewall) implemented with comprehensive test coverage and Flash integration. Redis caching infrastructure fully implemented.

**Risk Assessment:** 🟡 **MEDIUM RISK** - The core challenge is not integration with an external framework, but the robust implementation of the `PlanValidator` service. This service is the critical "Symbolic Firewall" that must correctly interpret the AI's plan and prevent any invalid actions from being executed.

### 🚀 **Caching Strategy for Token Optimization**

**Objective:** Minimize redundant AI queries and token usage through intelligent caching of plans, validations, and entity states across conversation turns.

#### **Multi-Layer Caching Architecture**

1. **🔵 Plan Cache** - Cache validated plans for similar goals
   - **Key Structure:** `plan:{user_hash}:{goal_hash}:{world_state_hash}`
   - **TTL:** 5 minutes or until world state change
   - **Invalidation:** On entity updates affecting plan preconditions
   - **Storage:** Redis with JSON serialization

2. **🟢 Context Window Cache** - Keep recent entity states in memory
   - **Structure:** HashMap of recently accessed entities (last 2-3 turns)
   - **Integration:** Embedded in `EnrichedContext.context_cache`
   - **Benefits:** Avoid re-querying entities just accessed
   - **TTL:** Duration of conversation session

3. **🟡 Validation Result Cache** - Cache plan validation outcomes
   - **Key Structure:** `validation:{plan_hash}:{world_state_hash}:{user_hash}`
   - **TTL:** 3 minutes (shorter than plan cache)
   - **Purpose:** Skip re-validation of identical plans

#### **Implementation Details**

```rust
// EnrichedContext with integrated caching
pub struct EnrichedContext {
    // ... existing fields ...
    
    /// Context cache for avoiding repeated queries
    pub context_cache: Option<ContextCache>,
}

pub struct ContextCache {
    /// Entities accessed in recent turns
    pub recent_entities: HashMap<Uuid, CachedEntityState>,
    /// Recently validated plans that might be reusable
    pub recent_plans: Vec<(String, ValidatedPlan)>,
    /// Cache timestamp for TTL management
    pub cache_timestamp: DateTime<Utc>,
}
```

#### **Cache Integration Points**

- **PlanningService:** Check plan cache before AI generation
- **PlanValidator:** Cache validation results for reuse
- **TacticalAgent:** Maintain context cache across turns
- **EcsEntityManager:** Leverage existing Redis entity cache

#### **Handling Repetitive Requests**

**Scenario:** User asks "What's in the cantina?" twice in consecutive turns.

**Without Caching:**
- Turn 1: AI queries entities → Planning → Validation → Response (300+ tokens)
- Turn 2: AI queries same entities → Planning → Validation → Response (300+ tokens)
- **Total:** 600+ tokens wasted on redundant operations

**With Caching:**
- Turn 1: AI queries entities → Planning → Validation → Response → Cache results
- Turn 2: Context cache hit → Skip AI planning → Use cached validation → Response
- **Total:** 300 tokens + minimal overhead (80%+ reduction)

**Implementation Benefits:**
1. **Token Savings:** 70-90% reduction for repetitive queries
2. **Latency Improvement:** Sub-100ms responses for cached scenarios
3. **Cost Optimization:** Significant reduction in API costs
4. **Consistency:** Identical questions get consistent answers

*   **[x] Task 3.1: Define the Action Schema for the LLM Planner** ✅ **COMPLETED**
    *   **Objective:** Create the formal "language" that the LLM will use to construct plans. This schema is the contract between the AI's creative output and the game's logical rules.
    *   **Current State:** ✅ **COMPLETED** - Schema, types, and comprehensive test suites implemented
    *   **[x] Subtask 3.1.1:** Create a versioned JSON schema file (e.g., `backend/resources/planning/action_schema_v1.json`).
    *   **[x] Subtask 3.1.2:** Define the schema to include `actions`, where each action has a `name` (matching a tool from Epic 2), `parameters` (with types), `preconditions` (ECS state required), and `effects` (ECS state changes).
    *   **[x] Subtask 3.1.3:** Document the schema thoroughly, explaining how each part maps to the ECS and the `TacticalToolkit`. This documentation is critical for prompt engineering.
    *   **[x] Subtask 3.1.4:** Write comprehensive tests for schema validation and type serialization.
    *   **[x] Subtask 3.1.5:** Write OWASP Top 10 security tests for plan validation.

*   **[x] Task 3.2: Implement the LLM-based Planning Service** ✅ **COMPLETED**
    *   **Objective:** Create the service that translates a narrative goal into a structured, AI-generated plan.
    *   **Current State:** ✅ **COMPLETED** - Full planning service with Flash integration, comprehensive tests, and security validation
    *   **[x] Subtask 3.2.1:** Create a new `backend/src/services/planning/mod.rs` module and a `PlanningService`.
    *   **[x] Subtask 3.2.2:** Implement a `PlanningService::generate_plan` method. This method will:
        *   [x] Accept a high-level goal (e.g., "Sol needs to get the datapad from Borga").
        *   [x] Query the ECS for relevant world state (characters, locations, relationships).
        *   [x] Construct a detailed prompt for the LLM, providing the goal, the current world state, and the `Action Schema` as a "function calling" or "tool use" definition.
        *   [x] Call the AI service (Flash) and request a plan as a JSON object conforming to the schema.
        *   [x] Implement robust fallback handling for AI response parsing failures.
        *   [x] Add intelligent goal-based action generation for enhanced reliability.
    *   **[x] Subtask 3.2.3:** Comprehensive test suite implementation:
        *   [x] Basic functionality tests (service creation, simple plans, complex multi-step plans)
        *   [x] Flash model integration tests with gemini-2.5-flash
        *   [x] Plan caching framework with Redis (cache key generation, user isolation)
        *   [x] World state context integration with EnrichedContext
        *   [x] Complete OWASP Top 10 security tests (A01: Access Control, A02: Encryption, A03: Injection, A04: Cache Security, A05: Misconfiguration, A06: Vulnerable Components, A07: Authentication Failures, A08: Data Integrity, A09: Error Handling, A10: SSRF Prevention)
        *   [x] 17 comprehensive test scenarios covering all major functionality
        *   [x] Security compliance validation for enterprise deployment
    *   **[x] Subtask 3.2.4 (Security - A02):** The `generate_plan` method MUST require a `SessionDek` to decrypt the necessary world state data for constructing the prompt.
        *   [x] Full SessionDek integration replacing test SecretBox implementations
        *   [x] End-to-end encryption for all world state queries
        *   [x] Secure encrypted context building with proper access control
        *   [x] User isolation and data separation enforcement
    *   **[x] Subtask 3.2.5:** Production readiness and performance optimization:
        *   [x] Redis caching with 5-minute TTL and AsyncCommands integration
        *   [x] Intelligent fallback handling for AI response parsing
        *   [x] Comprehensive plan validation with proper error handling
        *   [x] All compilation errors resolved (0 errors, warnings only)
        *   [x] Robust goal-based action generation with validation
        *   [x] Complete removal of TODO logic with proper implementations

*   **[x] Task 3.3: Implement the Plan Validator (The "Symbolic Firewall")** ✅ **COMPLETED**
    *   **Objective:** Create the critical service that validates the AI's plan against the ground truth of the ECS. **No action is executed without passing this check.**
    *   **Current State:** ✅ **FULLY IMPLEMENTED** - Complete Symbolic Firewall implementation with comprehensive validation checks and test coverage
    *   **[x] Subtask 3.3.1:** Create a `PlanValidatorService` in the `planning` module.
    *   **[x] Subtask 3.3.2:** Implement a `PlanValidatorService::validate_plan` method that takes the JSON plan from the LLM and validates against current ECS state.
    *   **[x] Subtask 3.3.3:** For each step in the plan, the validator checks:
        *   [x] **Action Validity:** Validates action exists in our `TacticalToolkit` (ActionName enum validation)
        *   [x] **Parameter Validity:** Validates entities and values passed as parameters exist and are accessible by the user
        *   [x] **Precondition Fulfillment:** Validates all precondition types against current ECS state:
            *   [x] `entity_exists`: Validates entity existence and user ownership
            *   [x] `entity_at_location`: Validates entity location relationships via ParentLink components
            *   [x] `entity_has_component`: Validates component presence and type
            *   [x] `inventory_has_space`: Validates inventory capacity and available slots
            *   [x] `relationship_exists`: Validates relationships and trust level requirements
        *   [x] **Circular Dependency Detection**: Uses DFS algorithm to prevent infinite loops in action dependencies
    *   **[x] Subtask 3.3.4:** The service returns either a `ValidPlan` or an `InvalidPlan` result with detailed failure reasons and validation metadata.
    *   **[x] Subtask 3.3.5:** Comprehensive test coverage:
        *   [x] **Functional Tests (9 tests):** `plan_validator_tests.rs` - Complete validation scenarios including valid plans, invalid entities, precondition failures, missing components, insufficient inventory space, relationship trust validation, complex multi-step plans, circular dependencies, and caching validation
        *   [x] **Security Tests (11 tests):** `plan_validator_security_tests.rs` - Complete OWASP Top 10 compliance:
            *   [x] **A01 (Broken Access Control):** Cross-user entity access prevention, permission boundary validation
            *   [x] **A03 (Injection):** SQL injection protection, JSON injection prevention in parameters
            *   [x] **A04 (Insecure Design):** Plan complexity limits, DoS protection
            *   [x] **A05 (Security Misconfiguration):** Error information leakage prevention
            *   [x] **A07 (Authentication Failures):** User context validation, nil user ID handling
            *   [x] **A08 (Data Integrity):** Plan validation consistency, inventory constraint enforcement
            *   [x] **A09 (Logging/Monitoring):** Plan validation audit trail, security event logging
            *   [x] **A10 (SSRF):** External reference prevention in plan parameters
            *   [x] **Comprehensive Security:** Malicious plan pattern detection with combined attack vectors
    *   **[x] Subtask 3.3.6:** Performance and caching implementation:
        *   [x] **Redis Caching:** Validation results cached with 3-minute TTL for performance optimization
        *   [x] **User Isolation:** All cache keys include user context for multi-tenant security
        *   [x] **Performance Metrics:** Validation timing and caching effectiveness tracking

*   **[ ] Task 3.4: Planning and Validation Integration Tests**
    *   **Objective:** Verify that the entire planning and validation loop works correctly.
    *   **File:** `backend/tests/planning_service_tests.rs` (new)
    *   **Current State:** ✅ Excellent test infrastructure exists with `test_helpers`.
    *   **[ ] Subtask 3.4.1: Write a "Valid Plan" Test:**
        1.  [ ] Use `test_helpers` to set up an initial world state (e.g., "Sol is in the Chamber").
        2.  [ ] Define a goal: "Sol wants to go to the Cantina."
        3.  [ ] Mock the AI call in `PlanningService` to return a correct, hardcoded JSON plan: `{"actions": [{"name": "move_entity", "parameters": ["Sol", "Cantina"]}]}`.
        4.  [ ] Call the `PlanningService`, then pass its output to the `PlanValidatorService`.
        5.  [ ] Assert that the plan is validated successfully.
    *   **[ ] Subtask 3.4.2: Write an "Invalid Plan" Test (Precondition Fail):**
        1.  [ ] Set up a world state where a precondition is not met (e.g., Sol needs a "keycard" to move, but doesn't have one).
        2.  [ ] Mock the AI to return the same plan as above.
        3.  [ ] Call the services and assert that the `PlanValidatorService` rejects the plan with a specific "PreconditionNotMet" error.
    *   **[ ] Subtask 3.4.3 (Security - A01):** Add a test where the goal involves an entity not owned by the user. Assert that the `PlanningService`'s world state query returns no data for that entity, leading to the `PlanValidatorService` rejecting any plan involving it.

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
   - [ ] Add security constraints to the `Action Schema` (e.g., marking certain actions as requiring admin privileges)

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