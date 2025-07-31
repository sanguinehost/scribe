# Agent Tool Access Control Matrix

This document defines the access control policies for tools available to different agents in the Sanguine Scribe system. It addresses the critical issue of multiple agents creating duplicate entities by establishing clear separation of concerns.

## Agent Types and Responsibilities

### 1. **Orchestrator Agent**
- **Role**: Coordinates all other agents, manages the overall workflow
- **Responsibilities**: 
  - Workflow orchestration
  - Agent coordination
  - High-level decision making
  - Result aggregation

### 2. **Perception Agent**
- **Role**: Observes and interprets the narrative world state
- **Responsibilities**:
  - Entity discovery and creation (EXCLUSIVE)
  - Initial entity classification
  - Narrative element extraction
  - World state observation

### 3. **Strategic Agent**
- **Role**: High-level planning and strategy
- **Responsibilities**:
  - Long-term narrative planning
  - Plot development strategy
  - Relationship dynamics planning
  - World-building strategy

### 4. **Tactical Agent**
- **Role**: Execution planning and immediate actions
- **Responsibilities**:
  - Action execution
  - Spatial relationship management
  - Immediate narrative responses
  - Entity interactions

### 5. **Chronicler Agent**
- **Role**: Records and preserves narrative events
- **Responsibilities**:
  - Chronicle event creation
  - Historical record keeping
  - Event significance assessment
  - Narrative preservation

## Tool Categories

### Entity Management Tools
- `CreateEntityTool` - Creates new entities
- `FindEntityTool` - Searches for existing entities
- `UpdateEntityTool` - Updates entity properties
- `GetEntityDetailsTool` - Retrieves entity information
- `DeleteEntityTool` - Removes entities (if exists)

### Spatial Tools
- `EstablishSpatialRelationshipTool` - Creates spatial relationships
- `UpdateSpatialRelationshipTool` - Modifies spatial relationships
- `QuerySpatialRelationshipsTool` - Queries spatial data
- `MovementTool` - Handles entity movement

### Relationship Tools
- `CreateRelationshipTool` - Creates social relationships
- `UpdateRelationshipTool` - Modifies relationships
- `QueryRelationshipsTool` - Queries relationship data

### Chronicle Tools
- `CreateChronicleEventTool` - Creates chronicle events
- `UpdateChronicleEventTool` - Updates events
- `QueryChronicleEventsTool` - Queries events

### Lorebook Tools
- `CreateLorebookEntryTool` - Creates lorebook entries
- `UpdateLorebookEntryTool` - Updates entries
- `QueryLorebookTool` - Queries lorebook

### Analysis Tools
- `AnalyzeTextSignificanceTool` - Analyzes narrative significance
- `ExtractTemporalEventsTool` - Extracts time-based events
- `ExtractWorldConceptsTool` - Extracts world-building elements
- `EntityResolutionTool` - Resolves entity references

### Search Tools
- `SearchKnowledgeBaseTool` - Searches knowledge base
- `SemanticSearchTool` - Semantic search capabilities

## Access Control Matrix

| Tool | Orchestrator | Perception | Strategic | Tactical | Chronicler |
|------|--------------|------------|-----------|----------|------------|
| **Entity Management** |
| CreateEntityTool | ❌ | ✅ | ❌ | ❌ | ❌ |
| FindEntityTool | ✅ | ✅ | ✅ | ✅ | ✅ |
| UpdateEntityTool | ❌ | ✅ | ❌ | ✅ | ❌ |
| GetEntityDetailsTool | ✅ | ✅ | ✅ | ✅ | ✅ |
| DeleteEntityTool | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Spatial Tools** |
| EstablishSpatialRelationshipTool | ❌ | ❌ | ❌ | ✅ | ❌ |
| UpdateSpatialRelationshipTool | ❌ | ❌ | ❌ | ✅ | ❌ |
| QuerySpatialRelationshipsTool | ✅ | ✅ | ✅ | ✅ | ✅ |
| MovementTool | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Relationship Tools** |
| CreateRelationshipTool | ❌ | ✅ | ❌ | ✅ | ❌ |
| UpdateRelationshipTool | ❌ | ❌ | ✅ | ✅ | ❌ |
| QueryRelationshipsTool | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Chronicle Tools** |
| CreateChronicleEventTool | ❌ | ❌ | ❌ | ❌ | ✅ |
| UpdateChronicleEventTool | ❌ | ❌ | ❌ | ❌ | ✅ |
| QueryChronicleEventsTool | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Lorebook Tools** |
| CreateLorebookEntryTool | ❌ | ❌ | ✅ | ❌ | ✅ |
| UpdateLorebookEntryTool | ❌ | ❌ | ✅ | ❌ | ✅ |
| QueryLorebookTool | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Analysis Tools** |
| AnalyzeTextSignificanceTool | ✅ | ✅ | ✅ | ❌ | ✅ |
| ExtractTemporalEventsTool | ❌ | ✅ | ❌ | ❌ | ✅ |
| ExtractWorldConceptsTool | ❌ | ✅ | ✅ | ❌ | ❌ |
| EntityResolutionTool | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Search Tools** |
| SearchKnowledgeBaseTool | ✅ | ✅ | ✅ | ✅ | ✅ |
| SemanticSearchTool | ✅ | ✅ | ✅ | ✅ | ✅ |

## Key Principles

### 1. **Exclusive Entity Creation**
Only the Perception Agent has access to `CreateEntityTool`. This prevents duplicate entity creation by ensuring a single source of truth for new entities.

### 2. **Read Access is Universal**
All agents have access to query/read tools (`Find*`, `Get*`, `Query*`, `Search*`) to ensure they can reference existing data.

### 3. **Update Access is Role-Based**
- Perception Agent: Can update entities it creates
- Tactical Agent: Can update spatial relationships and execute movements
- Strategic Agent: Can update high-level relationships
- Chronicler Agent: Exclusive access to chronicle creation

### 4. **Deletion is Restricted**
Entity deletion is currently not permitted for any agent to maintain data integrity.

### 5. **Analysis Tools are Shared**
Most analysis tools are available to multiple agents as they don't modify state.

## Implementation Guidelines

### Tool Security Policy Example
```rust
fn security_policy(&self) -> ToolSecurityPolicy {
    ToolSecurityPolicy {
        allowed_agents: vec![
            AgentType::Perception,  // Only Perception Agent
        ],
        required_capabilities: vec![],
        rate_limit: Some(RateLimit {
            calls_per_minute: 100,
            calls_per_hour: 1000,
            burst_size: 10,
        }),
        data_access: DataAccessPolicy {
            user_data: true,
            system_data: false,
            write_access: true,  // Can create entities
            allowed_scopes: vec!["entities".to_string()],
        },
        audit_level: AuditLevel::Full,  // Full audit for entity creation
    }
}
```

### Workflow Example: Entity Creation
1. **Orchestrator** receives narrative text
2. **Orchestrator** sends text to **Perception Agent**
3. **Perception Agent** uses `EntityResolutionTool` to check for existing entities
4. **Perception Agent** uses `CreateEntityTool` for new entities only
5. **Perception Agent** returns entity IDs to **Orchestrator**
6. **Orchestrator** passes entity IDs to other agents
7. **Strategic/Tactical Agents** use `FindEntityTool` and `GetEntityDetailsTool` to reference entities
8. **Tactical Agent** uses spatial tools to establish relationships
9. **Chronicler Agent** records significant events

## Migration Plan

### Phase 1: Update Tool Security Policies ✅
- [x] Update `CreateEntityTool` to only allow Perception Agent
- [x] Update `UpdateEntityTool` to only allow Perception and Tactical agents
- [x] Update `MoveEntityTool` to only allow Tactical Agent
- [x] Update relationship tools:
  - [x] `CreateRelationshipTool` - Perception and Tactical only
  - [x] `UpdateRelationshipTool` - Strategic and Tactical only
  - [x] `DeleteRelationshipTool` - No agents (disabled)
- [x] Update `CreateChronicleEventTool` to only allow Chronicler Agent
- [x] Update analysis tools:
  - [x] `AnalyzeTextSignificanceTool` - Orchestrator, Perception, Strategic, Chronicler
  - [x] `ExtractTemporalEventsTool` - Perception and Chronicler only
  - [x] `ExtractWorldConceptsTool` - Perception and Strategic only

### Phase 2: Update Agent Tool Registries
- [ ] Remove `CreateEntityTool` from Strategic Agent registry
- [ ] Remove `CreateEntityTool` from Tactical Agent registry
- [ ] Remove `CreateEntityTool` from Chronicler Agent registry

### Phase 3: Update Agent Prompts
- [ ] Update Perception Agent prompt to emphasize entity creation responsibility
- [ ] Update other agent prompts to use Find/Get tools instead of Create

### Phase 4: Testing
- [ ] Test that only Perception Agent can create entities
- [ ] Test that duplicate entities are no longer created
- [ ] Test that all agents can still function with read-only access

## Monitoring and Compliance

### Metrics to Track
1. Entity creation count by agent type
2. Duplicate entity creation attempts (should be 0)
3. Tool access violations (should be 0)
4. Entity resolution cache hit rate

### Audit Requirements
- All entity creation must be logged with full audit trail
- Failed access attempts must be logged
- Regular review of access patterns

## Future Considerations

1. **Dynamic Access Control**: Consider implementing role-based access that can be configured at runtime
2. **Capability-Based Access**: Move from agent-type to capability-based access control
3. **Tool Composition**: Allow certain tools to be composed from smaller, more focused tools
4. **Access Delegation**: Allow temporary access delegation for specific workflows

## Conclusion

This access control matrix solves the duplicate entity creation problem by establishing clear separation of concerns. Only the Perception Agent can create entities, while other agents work with existing entities through read and update operations. This ensures data consistency and prevents the race conditions that lead to duplicate entities.