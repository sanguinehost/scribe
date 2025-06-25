# Narrative Event System Design

## 1. Overview

This document details the design for a robust, hierarchical narrative event system for Scribe. The goal is to create a semantically rich and abstract system that allows an AI to comprehend, analyze, and generate narrative developments with greater accuracy and utility. This system evolves from simple event strings (e.g., `plot.twist.revealed`) to a structured, multi-level taxonomy.

This design is based on the principle of providing both high-level summaries for broad analysis and detailed, specific event types for granular logging and reasoning.

## 2. A Hierarchical Approach to Narrative Events

A hierarchical structure provides both high-level summaries and detailed, specific event logging. This allows for more flexible and powerful narrative analysis.

### 2.1. Level 1: Core Narrative Pillars (The "Why")

This level represents the highest-level categories of narrative change. Almost all significant events can be broadly classified into one of these pillars.

*   **`WORLD`**: Events that alter the state of the game world, its lore, or its physical properties.
*   **`CHARACTER`**: Events that primarily affect a specific character's internal or external state.
*   **`PLOT`**: Events that drive the main narrative or a significant side-narrative forward.
*   **`RELATIONSHIP`**: Events that change the dynamics between two or more entities (characters, factions, etc.).

### 2.2. Level 2: Abstract Event Categories (The "What")

This level provides a good balance of detail and abstraction, grouped under the Level 1 pillars.

*   **`WORLD`**
    *   **`DISCOVERY`**: The uncovering of new information or tangible things within the world.
        *   *Examples*: `LOCATION_DISCOVERY`, finding a new recipe, learning a new crafting technique.
    *   **`ALTERATION`**: A fundamental change to the world itself.
        *   *Examples*: `WORLD_CHANGE` (cleansing Mount Everest), a magical cataclysm, the political collapse of a kingdom.
    *   **`LORE_EXPANSION`**: The revelation of new knowledge about the world's history, mechanics, or inhabitants.
        *   *Examples*: `WORLD_KNOWLEDGE`, discovering the origin of a species, learning about a past war.

*   **`CHARACTER`**
    *   **`STATE_CHANGE`**: A change in a character's physical or mental condition.
        *   *Examples*: `CHARACTER_DEATH`, `CHARACTER_INJURY`, gaining a temporary buff, being afflicted by a curse.
    *   **`DEVELOPMENT`**: A change in a character's skills, abilities, or personality.
        *   *Examples*: `CHARACTER_GROWTH`, `POWER_GAINED`, `TRANSFORMATION`, learning a new skill, a change in alignment.
    *   **`INVENTORY_CHANGE`**: The acquisition or loss of items.
        *   *Examples*: `ITEM_ACQUISITION`, an item being stolen, an item being consumed.

*   **`PLOT`**
    *   **`PROGRESSION`**: The advancement of a known objective or storyline.
        *   *Examples*: `QUEST_PROGRESS`, completing a milestone in a larger plan.
    *   **`REVELATION`**: The uncovering of information that directly impacts the plot.
        *   *Examples*: `SECRET_REVELATION`, a major plot twist.
    *   **`TURNING_POINT`**: A critical moment of choice or a pivotal event that changes the direction of the plot.
        *   *Examples*: `DECISION_POINT`, an unexpected betrayal, the introduction of a new antagonist.

*   **`RELATIONSHIP`**
    *   **`FORMATION`**: The beginning of a new relationship.
        *   *Examples*: Meeting a new character for the first time (`CHARACTER_MET`), forming an alliance.
    *   **`MODIFICATION`**: A change in the nature of an existing relationship.
        *   *Examples*: `RELATIONSHIP_CHANGE` (friends becoming rivals), a shift in faction reputation.
    *   **`INTERACTION`**: A significant social exchange that has the potential to affect relationships or the plot.
        *   *Examples*: `SOCIAL_INTERACTION`, a key piece of dialogue, a successful negotiation.

### 2.3. Level 3: Specific Event Types (The "How")

This level consists of more specific event types, which can be mapped to the Level 2 categories. This allows for detailed analysis while still being able to roll up to the more abstract layers.

*   `PLOT_DEVELOPMENT` (Level 2: `PROGRESSION` or `TURNING_POINT`)
*   `CHARACTER_GROWTH` (Level 2: `DEVELOPMENT`)
*   `CHARACTER_DEATH` (Level 2: `STATE_CHANGE`)
*   `CHARACTER_INJURY` (Level 2: `STATE_CHANGE`)
*   `LOCATION_DISCOVERY` (Level 2: `DISCOVERY`)
*   `QUEST_PROGRESS` (Level 2: `PROGRESSION`)
*   `ITEM_ACQUISITION` (Level 2: `INVENTORY_CHANGE`)
*   `SECRET_REVELATION` (Level 2: `REVELATION`)
*   `RELATIONSHIP_CHANGE` (Level 2: `MODIFICATION`)
*   `WORLD_KNOWLEDGE` (Level 2: `LORE_EXPANSION`)
*   `SOCIAL_INTERACTION` (Level 2: `INTERACTION`)
*   `DECISION_POINT` (Level 2: `TURNING_POINT`)
*   `WORLD_CHANGE` (Level 2: `ALTERATION`)
*   `POWER_GAINED` (Level 2: `DEVELOPMENT`)
*   `TRANSFORMATION` (Level 2: `DEVELOPMENT`)

Further granularity can be introduced as sub-types. For example:
*   **`RELATIONSHIP_CHANGE`**
    *   `POSITIVE`: An improvement in the relationship (e.g., becoming friends, gaining trust).
    *   `NEGATIVE`: A degradation in the relationship (e.g., an argument, a betrayal).
    *   `NEUTRAL`: A change in the nature of the relationship without a clear positive or negative leaning (e.g., a professional relationship becoming personal).

## 3. Action vs. Outcome Duality

Events can also be structured by distinguishing between the action taken and its outcome.

*   **Action-Based Events**: Describe what a character or the world *does*.
    *   `COMBAT_ENCOUNTER`
    *   `EXPLORATION`
    *   `SOCIAL_INTERACTION`
    *   `DECISION_POINT`

*   **Outcome-Based Events**: Describe the result of an action.
    *   `CHARACTER_DEATH` (the outcome of a `COMBAT_ENCOUNTER` or a failed `DECISION_POINT`)
    *   `LOCATION_DISCOVERY` (the outcome of `EXPLORATION`)
    *   `RELATIONSHIP_CHANGE` (the outcome of a `SOCIAL_INTERACTION`)
    *   `CONSEQUENCE` (this is inherently an outcome)

The system can blend these, which is often more practical. For instance, `COMBAT_ENCOUNTER` can be a wrapper for a series of smaller outcome events.

## 4. Recommendations for Scribe

1.  **Adopt a Two-Level Hierarchy:** For immediate practical use, a two-level system is recommended.
    *   **`event_category`**: A high-level category like `WORLD`, `CHARACTER`, `PLOT`, or `RELATIONSHIP`.
    *   **`event_type`**: The detailed list (`PLOT_DEVELOPMENT`, `CHARACTER_DEATH`, etc.).
    This allows the AI to tag an event with both a broad category and a specific type, enabling more nuanced queries.

2.  **Refine "CONSEQUENCE":** The event type `CONSEQUENCE` is a meta-category. It could be handled as a flag or a link between a `DECISION_POINT` and its resulting events, where a `DECISION_POINT` event has a list of subsequent event IDs that are its direct consequences.

3.  **Consider Event Subjects and Objects:** To make the system truly abstract, each event should be associated with the entities involved.
    *   **`subject`**: The primary entity initiating or experiencing the event.
    *   **`object`**: The entity being acted upon.
    *   **`involved_entities`**: A list of other characters, items, or locations relevant to the event.