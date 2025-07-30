# Distributed Planning Architecture Roadmap

## Overview

This document outlines the transition from our current centralized PlanningService to a distributed planning model where each agent type maintains its own planning capabilities tailored to its specific role and available tools.

## Current State

### Problems with Centralized Planning
1. **Tool Mismatch**: PlanningService tries to use tools from multiple agent types, causing validation failures
2. **Abstraction Leak**: Low-level tool names exposed in high-level planning
3. **Security Boundary Violations**: Plans generated with tools the executing agent cannot access
4. **Rigid Structure**: All agents forced to use same plan format regardless of their needs

### Affected Files
- `/backend/src/services/planning/planning_service.rs` - Centralized planning logic
- `/backend/src/services/planning/types.rs` - Monolithic plan types
- `/backend/src/services/planning/plan_validator.rs` - Validates against UnifiedToolRegistry
- `/backend/src/services/agentic/tactical_agent.rs` - Currently calls PlanningService

## Target Architecture

### Core Principles
1. **Agent-Specific Planning**: Each agent plans using only its available tools
2. **Hierarchical Plans**: Plan abstraction matches agent's level in hierarchy
3. **Cross-Agent Coordination**: Plans can request capabilities from other agents
4. **Type Safety**: Agent-specific plan types prevent tool misuse

### New Architecture Components
```
StrategicAgent
  └── plan_narrative_arc() -> StrategicPlan
  
TacticalAgent
  └── plan_execution_sequence() -> TacticalPlan
  
PerceptionAgent
  └── plan_state_extraction() -> PerceptionPlan
  
OrchestratorAgent
  └── plan_agent_coordination() -> OrchestrationPlan
```

## Implementation Phases

### Phase 1: Create Agent-Specific Plan Types (Week 1)

**Objective**: Define plan structures that match each agent's mental model

**Tasks**:
1. Create `/backend/src/services/agentic/planning/mod.rs`
2. Define agent-specific plan types:
   ```rust
   // strategic_plans.rs
   pub struct StrategicPlan {
       narrative_goals: Vec<NarrativeGoal>,
       thematic_elements: Vec<Theme>,
       dramatic_beats: Vec<DramaticBeat>,
   }
   
   // tactical_plans.rs
   pub struct TacticalPlan {
       execution_steps: Vec<TacticalStep>,
       dependencies: DependencyGraph,
       resource_requirements: ResourceMap,
   }
   
   // perception_plans.rs
   pub struct PerceptionPlan {
       extraction_patterns: Vec<ExtractionPattern>,
       entity_resolution_strategy: ResolutionStrategy,
       state_update_sequence: Vec<StateUpdate>,
   }
   ```

**Security Considerations**:
- Plan types must not leak cross-agent tool names
- Each plan type validates against its agent's tool registry
- No direct tool invocation from plan structures

**Files to Create**:
- `/backend/src/services/agentic/planning/mod.rs`
- `/backend/src/services/agentic/planning/strategic_plans.rs`
- `/backend/src/services/agentic/planning/tactical_plans.rs`
- `/backend/src/services/agentic/planning/perception_plans.rs`
- `/backend/src/services/agentic/planning/orchestration_plans.rs`

### Phase 2: Embed Planning Logic in Agents (Week 2)

**Objective**: Move planning capabilities into each agent implementation

**Tasks**:
1. Add planning methods to each agent:
   ```rust
   impl StrategicAgent {
       async fn plan_narrative_arc(
           &self,
           context: &SharedAgentContext,
           session_dek: &SessionDek,
       ) -> Result<StrategicPlan, AppError> {
           // Use only strategic tools for planning
       }
   }
   ```

2. Update agent workflows to use embedded planning
3. Remove calls to centralized PlanningService

**Security Considerations**:
- Planning must use agent's specific UnifiedToolRegistry entries
- Session DEK required for accessing encrypted context
- Audit logging for all planning decisions

**Files to Modify**:
- `/backend/src/services/agentic/strategic_agent.rs`
- `/backend/src/services/agentic/tactical_agent.rs`
- `/backend/src/services/agentic/perception_agent.rs`
- `/backend/src/services/agentic/orchestrator.rs`

### Phase 3: Implement Cross-Agent Request System (Week 3)

**Objective**: Allow plans to request capabilities from other agents

**Tasks**:
1. Create request/response protocol:
   ```rust
   pub enum AgentRequest {
       AnalyzeNarrative { text: String },
       ExtractEntities { context: String },
       FindSpatialContext { entity_id: Uuid },
   }
   
   pub struct CrossAgentStep {
       target_agent: AgentType,
       request: AgentRequest,
       timeout: Duration,
   }
   ```

2. Implement request routing through SharedAgentContext
3. Add request validation and authorization

**Security Considerations**:
- Requests must be validated against agent capabilities
- No direct tool access across agent boundaries
- Request/response audit trail required
- Timeout enforcement to prevent blocking

**Files to Create**:
- `/backend/src/services/agentic/planning/cross_agent_protocol.rs`
- `/backend/src/services/agentic/planning/request_router.rs`

### Phase 4: Migrate Existing Planning Logic (Week 4)

**Objective**: Safely transition from centralized to distributed planning

**Tasks**:
1. Create migration shim in PlanningService:
   ```rust
   impl PlanningService {
       #[deprecated(note = "Use agent-specific planning methods")]
       pub async fn generate_plan(...) -> Result<AiGeneratedPlan, AppError> {
           // Route to appropriate agent based on context
       }
   }
   ```

2. Update all test files to use new planning methods
3. Add feature flag for gradual rollout

**Security Considerations**:
- Maintain backward compatibility during migration
- Extensive testing of permission boundaries
- Monitor for planning failures during transition

**Files to Modify**:
- `/backend/src/services/planning/planning_service.rs` (deprecate)
- `/backend/tests/planning_service_tests.rs`
- `/backend/tests/planning_service_integration_tests.rs`
- `/backend/tests/planning_service_security_tests.rs`

### Phase 5: Remove Centralized Planning (Week 5)

**Objective**: Complete transition to distributed planning

**Tasks**:
1. Remove deprecated PlanningService
2. Delete centralized plan types
3. Update all documentation
4. Performance benchmarking

**Files to Delete**:
- `/backend/src/services/planning/planning_service.rs`
- `/backend/src/services/planning/types.rs`
- `/backend/src/services/planning/structured_output.rs`

**Files to Create**:
- `/backend/docs/planning_architecture.md`
- `/backend/benches/distributed_planning_bench.rs`

## Success Metrics

1. **Functional**: All end-to-end tests pass with distributed planning
2. **Security**: No cross-agent tool access violations
3. **Performance**: Planning latency ≤ current centralized approach
4. **Maintainability**: Agent-specific planning logic isolated and testable

## Risk Mitigation

### Rollback Strategy
- Feature flags allow instant reversion to centralized planning
- Migration shim maintains compatibility during transition
- Comprehensive test coverage before each phase

### Performance Risks
- Distributed planning may increase overall latency
- Mitigation: Parallel planning where possible, caching strategies

### Complexity Risks
- More moving parts than centralized approach
- Mitigation: Strong type safety, comprehensive documentation

## Testing Strategy

### Unit Tests
- Each agent's planning logic tested in isolation
- Mock cross-agent requests
- Validate tool access restrictions

### Integration Tests
- End-to-end planning workflows
- Cross-agent request handling
- Session DEK encryption/decryption

### Security Tests
- Attempt cross-agent tool access (should fail)
- Validate audit logging
- Test timeout enforcement

## Documentation Updates

1. Update `ARCHITECTURE.md` with distributed planning model
2. Create planning guides for each agent type
3. Document cross-agent request protocol
4. Update `CLAUDE.md` with planning best practices

## Timeline

- **Week 1**: Phase 1 - Agent-specific plan types
- **Week 2**: Phase 2 - Embed planning in agents
- **Week 3**: Phase 3 - Cross-agent requests
- **Week 4**: Phase 4 - Migration
- **Week 5**: Phase 5 - Cleanup and optimization
- **Week 6**: Documentation and benchmarking

## Notes

This architecture better aligns with the principle of hierarchical responsibility. Each agent becomes truly autonomous within its domain while maintaining clear interfaces for coordination. The distributed model also improves testability, security, and allows each agent type to evolve its planning strategies independently.