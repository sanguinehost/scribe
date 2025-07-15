# EnrichedContext Schema Documentation

## Overview

The `EnrichedContext` schema represents the formal API contract between the symbolic world model (Tactical Layer) and neural generation systems (LLM Prompt Generation). This document defines the structure, versioning, and validation requirements for `EnrichedContext` payloads.

## Schema Version

Current Version: **1.0**

## Core Structure

```rust
pub struct EnrichedContext {
    // Strategic Layer Output
    pub strategic_directive: Option<StrategicDirective>,
    
    // Tactical Layer Output
    pub validated_plan: ValidatedPlan,
    pub current_sub_goal: SubGoal,
    
    // World State Context
    pub relevant_entities: Vec<EntityContext>,
    pub spatial_context: Option<SpatialContext>,
    pub causal_context: Option<CausalContext>,
    pub temporal_context: Option<TemporalContext>,
    
    // Validation Metadata
    pub plan_validation_status: PlanValidationStatus,
    pub symbolic_firewall_checks: Vec<ValidationCheck>,
    
    // Legacy Support
    pub assembled_context: Option<String>,
    
    // Performance Metrics
    pub total_tokens_used: u32,
    pub execution_time_ms: u64,
    pub validation_time_ms: u64,
    pub ai_model_calls: u32,
    pub confidence_score: f32,
}
```

## Required Fields

The following fields MUST be populated in all valid `EnrichedContext` payloads:

1. **current_sub_goal.description** - Non-empty description of the immediate goal
2. **current_sub_goal.actionable_directive** - Non-empty directive for execution
3. **validated_plan** - Must contain a valid plan structure
4. **confidence_score** - Must be between 0.0 and 1.0

## Field Specifications

### Strategic Directive

```rust
pub struct StrategicDirective {
    pub directive_id: Uuid,
    pub directive_type: String,
    pub narrative_arc: String,
    pub plot_significance: PlotSignificance,
    pub emotional_tone: String,
    pub character_focus: Vec<String>,
    pub world_impact_level: WorldImpactLevel,
}
```

- **directive_type**: Category of narrative action (e.g., "exploration", "combat", "dialogue")
- **plot_significance**: Enum values: Major, Moderate, Minor, Trivial
- **world_impact_level**: Enum values: Global, Regional, Local, Personal

### Validated Plan

```rust
pub struct ValidatedPlan {
    pub plan_id: Uuid,
    pub steps: Vec<PlanStep>,
    pub preconditions_met: bool,
    pub causal_consistency_verified: bool,
    pub entity_dependencies: Vec<String>,
    pub estimated_execution_time: Option<u64>,
    pub risk_assessment: RiskAssessment,
}
```

### Entity Context

```rust
pub struct EntityContext {
    pub entity_id: Uuid,
    pub entity_name: String,
    pub entity_type: String,
    pub current_state: HashMap<String, Value>,
    pub spatial_location: Option<SpatialLocation>,
    pub relationships: Vec<EntityRelationship>,
    pub recent_actions: Vec<String>,
    pub emotional_state: Option<EmotionalState>,
    pub narrative_importance: f32,  // 0.0 to 1.0
    pub ai_insights: Vec<String>,
}
```

## Validation Rules

### Schema Validation

1. **Field Presence**: All required fields must be present
2. **Value Ranges**: Numeric fields must be within valid ranges
3. **String Fields**: Required strings must be non-empty
4. **Consistency**: Related fields must be logically consistent

### Business Logic Validation

1. **Plan-Goal Alignment**: Current sub-goal must align with validated plan
2. **Entity Relevance**: Entities must be relevant to the current context
3. **Temporal Consistency**: Temporal context must be logically consistent

## Token Optimization

### Compact Representation

For token efficiency, use the `CompactEnrichedContext` representation when sending to LLMs:

```rust
pub struct CompactEnrichedContext {
    pub sd_id: Option<Uuid>,
    pub goal: CompactSubGoal,
    pub entities: Vec<CompactEntity>,
    pub plan: CompactPlan,
    pub metrics: CompactMetrics,
}
```

### Optimization Guidelines

1. **Use IDs over full objects** when possible
2. **Abbreviate field names** in compact representation
3. **Omit null/empty fields** in JSON serialization
4. **Aggregate related data** to reduce nesting

## Version Migration

### Version 1.0 → Future Versions

When adding new fields:
1. Make new fields optional to maintain backward compatibility
2. Provide sensible defaults for missing fields
3. Document migration path in this document

### Version Detection

Always include schema version in serialized payloads:

```json
{
  "schema_version": "1.0",
  "created_at": "2024-01-15T10:30:00Z",
  "strategic_directive": { ... },
  // ... rest of EnrichedContext
}
```

## Usage Examples

### Creating a Valid EnrichedContext

```rust
let enriched_context = EnrichedContext {
    strategic_directive: Some(StrategicDirective {
        directive_id: Uuid::new_v4(),
        directive_type: "exploration".to_string(),
        narrative_arc: "Investigate the mysterious warehouse".to_string(),
        plot_significance: PlotSignificance::Moderate,
        emotional_tone: "tense".to_string(),
        character_focus: vec!["Player".to_string()],
        world_impact_level: WorldImpactLevel::Local,
    }),
    validated_plan: ValidatedPlan {
        plan_id: Uuid::new_v4(),
        steps: vec![
            PlanStep {
                step_id: Uuid::new_v4(),
                description: "Approach warehouse entrance".to_string(),
                // ... other fields
            }
        ],
        preconditions_met: true,
        // ... other fields
    },
    current_sub_goal: SubGoal {
        goal_id: Uuid::new_v4(),
        description: "Scout the warehouse perimeter".to_string(),
        actionable_directive: "Move carefully around the building".to_string(),
        // ... other fields
    },
    // ... rest of fields
};
```

### Validating EnrichedContext

```rust
use crate::services::context_assembly_engine::validate_enriched_context;

let validation_result = validate_enriched_context(&enriched_context);
if !validation_result.is_valid {
    for error in &validation_result.errors {
        error!("Validation error in {}: {}", error.field, error.message);
    }
}
```

## Integration Points

### Prompt Builder Integration

The prompt builder consumes `EnrichedContext` and formats it for LLM consumption:

```rust
let (system_prompt, messages) = build_enriched_context_prompt(
    EnrichedPromptBuildParams {
        enriched_context: Some(&enriched_context),
        // ... other params
    }
).await?;
```

### Chat Service Integration

The chat service uses TacticalAgent to produce `EnrichedContext`:

```rust
let enriched_context = tactical_agent.process_directive(
    &strategic_directive,
    user_id,
    &session_dek,
).await?;
```

## Future Enhancements

### Version 2.0 Candidates

1. **Multi-agent coordination** fields
2. **Parallel action** support
3. **Conditional planning** structures
4. **Resource management** tracking
5. **Performance prediction** metadata

### Schema Evolution Process

1. Propose changes in GitHub issue
2. Implement as optional fields first
3. Test with existing integrations
4. Document migration path
5. Increment version when breaking changes required