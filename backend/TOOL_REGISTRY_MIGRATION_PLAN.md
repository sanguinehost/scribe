# Tool Registry Consolidation & Self-Registration Migration Plan

## Current State Analysis

### Registry Files to Consolidate:
1. **`registry.rs`** - Simple HashMap-based registry (old, basic)
2. **`tool_registry.rs`** - Static global registry with metadata (current, comprehensive)
3. **`tool_registration.rs`** - Manual registration functions (1300+ lines!)
4. **`tool_discovery.rs`** - Discovery service with hardcoded tool names

### Problems with Current Approach:
- Manual registration of 41+ tools in a single 1300+ line file
- No self-registration capability
- Hardcoded tool names in discovery service
- Confusing multiple registry implementations
- Difficult to add new tools (must remember to register them)
- No compile-time guarantee that all tools are registered

## Migration Plan - Task Breakdown

### Phase 1: Design New Unified Registry System
**Goal**: Create a single, self-registering tool registry based on `query_registry_v2.rs` pattern

#### Task 1.1: Design Unified Tool Registry API
- [ ] Create `tool_registry_unified.rs` combining best of all 4 files
- [ ] Support both static registration (for migration) and dynamic self-registration
- [ ] Include all metadata from current `tool_registry.rs`
- [ ] Add discovery capabilities from `tool_discovery.rs`
- [ ] Use global lazy static pattern from `query_registry_v2.rs`

#### Task 1.2: Create Self-Registration Infrastructure
- [ ] Create `register_tool!` macro for easy self-registration
- [ ] Add `#[tool]` procedural macro (optional, for cleaner syntax)
- [ ] Create initialization system that ensures all tools register at startup
- [ ] Add compile-time checks or tests to ensure no tools are missed

### Phase 2: Implement Tool Traits for Self-Registration
**Goal**: Update tool implementations to support self-registration

#### Task 2.1: Create Enhanced ScribeTool Trait
- [ ] Add `metadata()` method to ScribeTool trait returning ToolMetadata
- [ ] Add `register()` method with default implementation
- [ ] Ensure backward compatibility with existing ScribeTool implementations

#### Task 2.2: Create Tool Registration Module Pattern
- [ ] Each tool file gets a `register()` function at module level
- [ ] Use `ctor` crate or similar for automatic registration at startup
- [ ] Alternative: Use `inventory` crate for collecting implementations

### Phase 3: Migrate Individual Tools
**Goal**: Update each tool to self-register (41 tools total)

#### Task 3.1: Migrate Narrative Tools (7 tools)
- [ ] AnalyzeTextSignificanceTool - add self-registration
- [ ] CreateChronicleEventTool - add self-registration
- [ ] CreateLorebookEntryTool - add self-registration
- [ ] ExtractTemporalEventsTool - add self-registration
- [ ] ExtractWorldConceptsTool - add self-registration
- [ ] SearchKnowledgeBaseTool - add self-registration
- [ ] UpdateLorebookEntryTool - add self-registration

#### Task 3.2: Migrate Entity Management Tools (14 tools)
- [ ] EntityResolutionTool - add self-registration
- [ ] CreateEntityTool - add self-registration
- [ ] UpdateEntityTool - add self-registration
- [ ] GetEntityHierarchyTool - add self-registration
- [ ] PromoteEntityHierarchyTool - add self-registration
- [ ] FindEntityTool - add self-registration
- [ ] GetEntityDetailsTool - add self-registration
- [ ] GetContainedEntitiesTool - add self-registration
- [ ] GetSpatialContextTool - add self-registration
- [ ] MoveEntityTool - add self-registration
- [ ] AddItemToInventoryTool - add self-registration
- [ ] RemoveItemFromInventoryTool - add self-registration
- [ ] UpdateRelationshipTool - add self-registration
- [ ] GetVisibleEntitiesAndExitsTool - add self-registration

#### Task 3.3: Migrate AI-Powered Tools (9 tools)
- [ ] AssessCharacterImpactTool - add self-registration
- [ ] AssessEnvironmentTool - add self-registration
- [ ] AssessNarrativeOpportunitiesTool - add self-registration
- [ ] GenerateDescriptionTool - add self-registration
- [ ] GenerateNameTool - add self-registration
- [ ] GenerateWorldStateTool - add self-registration
- [ ] AnalyzeHierarchyRequestTool - add self-registration
- [ ] SuggestHierarchyPromotionTool - add self-registration
- [ ] UpdateSalienceTool - add self-registration

#### Task 3.4: Migrate Knowledge Tools (5 tools)
- [ ] QueryLorebookTool - add self-registration
- [ ] ManageLorebookTool - add self-registration
- [ ] QueryChronicleEventsTool - add self-registration
- [ ] QueryInventoryTool - add self-registration
- [ ] ManageInventoryTool - add self-registration

### Phase 4: Update Tool Discovery
**Goal**: Make tool discovery dynamic instead of hardcoded

#### Task 4.1: Implement Dynamic Discovery
- [ ] Update `ToolDiscoveryService` to query registry dynamically
- [ ] Use tool metadata tags and categories for recommendations
- [ ] Implement fuzzy matching on tool descriptions
- [ ] Add AI-powered tool recommendation (using tool metadata)

#### Task 4.2: Create Tool Search API
- [ ] Search by category
- [ ] Search by tags
- [ ] Search by capabilities (based on description)
- [ ] Search by workflow phase
- [ ] Get tools accessible by specific agent type

### Phase 5: Remove Old Registry Systems
**Goal**: Clean up redundant code

#### Task 5.1: Deprecate Old Files
- [ ] Mark `registry.rs` as deprecated
- [ ] Mark `tool_registry.rs` as deprecated
- [ ] Mark `tool_registration.rs` as deprecated
- [ ] Update all imports to use new unified registry

#### Task 5.2: Migration Testing
- [ ] Create comprehensive test suite for new registry
- [ ] Ensure all 41 tools are still registered
- [ ] Test discovery functionality
- [ ] Test agent access policies
- [ ] Performance testing (startup time with self-registration)

#### Task 5.3: Final Cleanup
- [ ] Remove deprecated files
- [ ] Update documentation
- [ ] Update CLAUDE.md with new tool registration process
- [ ] Create developer guide for adding new tools

### Phase 6: Implement Query Registry Migration
**Goal**: Apply same pattern to query registry

#### Task 6.1: Migrate to query_registry_v2
- [ ] Update all query types to self-register
- [ ] Remove static query_registry.rs
- [ ] Update query strategy planner to use dynamic registry

## Implementation Strategy

### Option A: Incremental Migration
1. Implement new unified registry alongside existing system
2. Migrate tools one by one
3. Run both systems in parallel during migration
4. Switch over once all tools migrated
5. Remove old system

**Pros**: Safe, can be done gradually
**Cons**: Temporary duplication, longer migration period

### Option B: Big Bang Migration
1. Implement new registry system
2. Migrate all tools in one PR
3. Remove old system immediately

**Pros**: Clean, no temporary duplication
**Cons**: Risky, large PR, potential for breakage

### Recommended Approach: **Option A (Incremental)**
- Lower risk
- Can be tested thoroughly at each step
- Easy to rollback if issues found
- Can be done by multiple developers in parallel

## Success Criteria

1. **All 41+ tools self-register** at startup
2. **No manual registration required** in a central file
3. **Single unified registry** implementation
4. **Dynamic tool discovery** based on metadata
5. **Compile-time safety** - build fails if tool not registered
6. **Improved developer experience** - easy to add new tools
7. **Performance maintained** - startup time not significantly impacted
8. **Full test coverage** of registration system

## Technical Decisions Needed

1. **Registration Method**: 
   - `ctor` crate for automatic registration?
   - `inventory` crate for collecting implementations?
   - Custom solution with explicit registration calls?

2. **Metadata Storage**:
   - Part of ScribeTool trait?
   - Separate metadata trait?
   - Attribute macros?

3. **Discovery Algorithm**:
   - Simple keyword matching?
   - AI-powered recommendations?
   - Rule-based system?

4. **Access Control**:
   - Keep current agent-based policies?
   - Add more granular permissions?
   - Runtime vs compile-time checks?

## Estimated Timeline

- **Phase 1**: 2-3 days (design and infrastructure)
- **Phase 2**: 1-2 days (trait updates)
- **Phase 3**: 3-4 days (migrate 41 tools)
- **Phase 4**: 1-2 days (discovery system)
- **Phase 5**: 1 day (cleanup and testing)
- **Phase 6**: 1-2 days (query registry migration)

**Total**: 10-16 days of development

## Next Steps

1. Review and approve this plan
2. Create feature branch for migration
3. Start with Phase 1 - designing unified registry
4. Create proof of concept with 1-2 tools
5. Get feedback before full migration