# The Scribe Narrative Event Schema
# Version 3.0

## 1. Overview: The Quantum of Story

This document provides the technical specification for the Scribe Narrative Event, the foundational data structure of the **Ars Fabula** narrative intelligence system. This schema is a direct implementation of the "Quantum of Story" concept, designed to capture the full semantic context of any narrative development.

Each event is a rich, multi-faceted data object stored in the `chronicle_events` table. This structure allows the system to move beyond simple logging to perform complex querying, causal reasoning, and sophisticated de-duplication.

## 2. The Event Schema

The following table details the fields of the `chronicle_events` table, which defines the structure of every narrative event in Scribe.

| Field | SQL Type | Rust Type | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `id` | `UUID` | `Uuid` | A unique, immutable identifier for the event instance. Primary Key. | `f47ac10b-58cc-4372-a567-0e02b2c3d479` |
| `chronicle_id` | `UUID` | `Uuid` | Foreign key linking the event to its parent chronicle. | `a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6` |
| `user_id` | `UUID` | `Uuid` | Foreign key linking the event to the user who owns it. | `b2c3d4e5-f6a7-b8c9-d0e1-f2a3b4c5d6e7` |
| `timestamp_iso8601` | `TIMESTAMPTZ` | `DateTime<Utc>` | The precise in-world time the event occurred. Essential for temporal reasoning and sorting. | `2251-08-15T14:30:00Z` |
| `event_type` | `VARCHAR(100)` | `String` | A hierarchical, dot-notation classification of the event. | `CHARACTER.STATE_CHANGE.DEATH` |
| `action` | `VARCHAR(100)` | `String` | The core verb of the event, representing the fundamental act that occurred. | `Betrayed` |
| `actors` | `JSONB` | `Vec<EventActor>` | A list of all entities participating in the event and their specific narrative roles. | `[{"role": "Agent", "id": "char_A"}, {"role": "Patient", "id": "char_B"}]` |
| `context_data` | `JSONB` | `JsonValue` | Spatio-temporal and situational information (Labov's "Orientation"). | `{"location_id": "loc_ThroneRoom", "time_of_day": "Night"}` |
| `causality` | `JSONB` | `EventCausality` | Links to other event IDs, forming a directed acyclic graph (DAG) of cause and effect. | `{"causedBy": ["evt_123"], "causes": ["evt_456"]}` |
| `valence` | `JSONB` | `Vec<EventValence>` | A vector representing the emotional or relational impact of the event. | `[{"target": "char_B", "type": "Trust", "change": -0.8}]` |
| `modality` | `VARCHAR(50)` | `String` | The reality status of the event, distinguishing objective truth from subjective belief. | `ACTUAL` or `BELIEVED_BY:char_C` |
| `summary` | `TEXT` | `String` | **[Legacy]** The original plaintext summary of the event. Will be deprecated. | `Lucas cleansed Mount Everest.` |
| `summary_encrypted` | `BYTEA` | `Vec<u8>` | The encrypted summary of the event, ensuring data privacy at rest. | `\xABC123...` |
| `summary_nonce` | `BYTEA` | `Vec<u8>` | The nonce used for the GCM encryption of the summary. | `\xDEF456...` |
| `source` | `VARCHAR(50)` | `String` | The origin of the event (`AI_EXTRACTED`, `USER_ADDED`, `GAME_API`). | `AI_EXTRACTED` |
| `event_data` | `JSONB` | `JsonValue` | **[Legacy]** An unstructured field for additional data. Will be deprecated. | `{"old_field": "old_value"}` |

## 3. Detailed Field Specifications

### 3.1. `actors` (`JSONB`)

Based on Propp's *dramatis personae*, this field captures the function of each participant.

*   **Structure:** An array of `EventActor` objects.
*   **`EventActor` Object:**
    *   `id` (UUID): The ID of the entity (character, item, location).
    *   `role` (String): The narrative role of the actor.
*   **Standard Roles:** `Agent`, `Patient`, `Beneficiary`, `Instrument`, `Helper`, `Opponent`, `Witness`.

**Example JSON:**
```json
[
  {
    "id": "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
    "role": "Agent"
  },
  {
    "id": "b2c3d4e5-f6a7-b8c9-d0e1-f2a3b4c5d6e7",
    "role": "Patient"
  }
]
```

### 3.2. `causality` (`JSONB`)

This field transforms the event log into a causal graph.

*   **Structure:** An `EventCausality` object.
*   **`EventCausality` Object:**
    *   `causedBy` (Array of UUIDs): A list of `event_id`s that were necessary preconditions for this event.
    *   `causes` (Array of UUIDs): A list of `event_id`s for which this event is a direct cause.

**Example JSON:**
```json
{
  "causedBy": ["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
  "causes": []
}
```

### 3.3. `valence` (`JSONB`)

This field quantifies the emotional or relational impact of the event.

*   **Structure:** An array of `EventValence` objects.
*   **`EventValence` Object:**
    *   `target` (UUID): The ID of the entity whose state is being affected.
    *   `type` (String): The type of value being changed (e.g., `Trust`, `Fear`, `Health`, `Power`).
    *   `change` (Float): A numerical value representing the change (e.g., `-0.8` for a large negative change).

**Example JSON:**
```json
[
  {
    "target": "b2c3d4e5-f6a7-b8c9-d0e1-f2a3b4c5d6e7",
    "type": "Trust",
    "change": -0.8
  }
]
```

### 3.4. `modality` (`VARCHAR`)

This field specifies the reality status of the event, which is critical for modeling belief vs. reality.

*   **Possible Values:**
    *   `ACTUAL`: The event is part of the ground-truth `Fabula`.
    *   `HYPOTHETICAL`: The event is part of a plan or "what if" scenario.
    *   `COUNTERFACTUAL`: The event describes what could have happened but didn't.
    *   `BELIEVED_BY:{agent_id}`: The event is believed to be true by a specific agent, regardless of its actual status.