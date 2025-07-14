# Action Schema Documentation for LLM Planning

## Overview

The Action Schema v1.0 defines the formal language that the LLM uses to construct executable plans within the Sanguine Scribe world simulation. This schema serves as the contract between the AI's creative narrative planning and the ECS's deterministic world state management.

## Core Concepts

### 1. **Actions**
Actions are atomic operations that map directly to world interaction tools from the Tactical Toolkit (Epic 2). Each action represents a single, verifiable change to the world state.

### 2. **Preconditions**
Preconditions define the required world state that must exist before an action can be executed. The Plan Validator (Symbolic Firewall) verifies these against the ECS ground truth.

### 3. **Effects**
Effects describe the expected world state changes after successful action execution. These are used for:
- Plan validation (ensuring logical consistency)
- Dynamic re-planning (detecting when reality diverges from expectations)
- Context caching (knowing what state changes to track)

## Action Types

### Entity Discovery Actions
- **find_entity**: Locate entities by name, scale, parent, or component
- **get_entity_details**: Retrieve detailed information about an entity
- **get_contained_entities**: Query spatial hierarchies
- **get_spatial_context**: Get full spatial context (ancestors + descendants)

### Entity Manipulation Actions
- **create_entity**: Create new entities with components
- **update_entity**: Modify entity components (add/update/remove)
- **move_entity**: Change entity spatial relationships

### Inventory Actions
- **add_item_to_inventory**: Add items with quantity/capacity checks
- **remove_item_from_inventory**: Remove items with validation

### Relationship Actions
- **update_relationship**: Modify trust/affection between entities

## Precondition Types

### 1. **entity_exists**
Verifies that required entities exist in the world state.
```json
{
  "entity_exists": [
    {"entity_id": "sol-uuid", "entity_name": "Sol"}
  ]
}
```

### 2. **entity_at_location**
Ensures entities are at specific locations before movement/interaction.
```json
{
  "entity_at_location": [
    {"entity_id": "sol-uuid", "location_id": "cantina-uuid"}
  ]
}
```

### 3. **entity_has_component**
Validates that entities have required components (e.g., Inventory before adding items).
```json
{
  "entity_has_component": [
    {"entity_id": "sol-uuid", "component_type": "Inventory"}
  ]
}
```

### 4. **inventory_has_space**
Checks available inventory capacity before adding items.
```json
{
  "inventory_has_space": {
    "entity_id": "sol-uuid",
    "required_slots": 1
  }
}
```

### 5. **relationship_exists**
Validates relationship requirements (e.g., minimum trust for transactions).
```json
{
  "relationship_exists": [
    {
      "source_entity": "sol-uuid",
      "target_entity": "borga-uuid",
      "min_trust": 0.3
    }
  ]
}
```

## Effect Types

### 1. **entity_moved**
Records spatial position changes.

### 2. **entity_created**
Tracks new entity creation with initial properties.

### 3. **component_updated**
Documents component modifications (add/update/remove operations).

### 4. **inventory_changed**
Tracks item quantity changes in inventories.

### 5. **relationship_changed**
Records trust/affection modifications between entities.

## Plan Structure

A complete plan contains:
1. **Goal**: High-level narrative objective
2. **Actions**: Ordered sequence of executable steps
3. **Metadata**: Confidence, duration estimates, alternatives considered

## Validation Process

The Plan Validator (Symbolic Firewall) performs these checks:

1. **Action Validity**: Does the action exist in our Tactical Toolkit?
2. **Parameter Validity**: Do referenced entities/values exist in the ECS?
3. **Precondition Satisfaction**: Is the required world state met?
4. **Effect Consistency**: Are the effects logically possible given preconditions?
5. **Dependency Order**: Are action dependencies properly sequenced?

## Example Plans

### Simple Movement
```json
{
  "goal": "Sol goes to the cantina",
  "actions": [
    {
      "name": "move_entity",
      "parameters": {
        "entity_to_move": "Sol",
        "new_parent": "Cantina"
      },
      "preconditions": {
        "entity_exists": [
          {"entity_name": "Sol"},
          {"entity_name": "Cantina"}
        ]
      },
      "effects": {
        "entity_moved": {
          "entity_id": "Sol",
          "new_location": "Cantina"
        }
      }
    }
  ]
}
```

### Complex Transaction
See the full example in the schema for a multi-step plan involving movement, relationship checks, and inventory transfers.

## Integration with Caching

The schema supports caching optimization through:
1. **Deterministic IDs**: Actions have unique IDs for cache key generation
2. **Clear Dependencies**: Enables partial plan caching and reuse
3. **Explicit Effects**: Allows tracking which plans are invalidated by world changes

## Prompt Engineering Guidelines

When constructing prompts for the LLM to generate plans:

1. **Provide the schema**: Include relevant schema sections in the prompt
2. **Give world context**: Current entity states, relationships, spatial hierarchy
3. **Specify constraints**: Time limits, resource availability, character capabilities
4. **Request structured output**: Explicitly ask for JSON conforming to the schema
5. **Include examples**: Show 1-2 relevant example plans for similar goals

## Version History

- **v1.0** (2025-01-13): Initial schema with core action types from Tactical Toolkit