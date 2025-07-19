//! Central Query Registry
//! 
//! This module provides a comprehensive registry of all available query types,
//! their parameters, usage patterns, and mappings to execution results.
//! This ensures AI agents have complete, accurate information about available tools.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json::Value as JsonValue;

/// Central registry for all query types and their metadata
pub struct QueryRegistry;

/// Metadata about a query type including parameters and usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryTypeMetadata {
    /// The query type name as used in PlannedQueryType enum
    pub name: &'static str,
    /// Human-readable description of what this query does
    pub description: &'static str,
    /// When to use this query type
    pub usage_guidance: &'static str,
    /// Required parameters for this query
    pub required_parameters: Vec<ParameterMetadata>,
    /// Optional parameters for this query
    pub optional_parameters: Vec<ParameterMetadata>,
    /// What this query returns
    pub returns: &'static str,
    /// Example usage
    pub example: &'static str,
    /// Dependencies on other query types
    pub dependencies: Vec<&'static str>,
    /// Typical token usage
    pub typical_tokens: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterMetadata {
    pub name: &'static str,
    pub type_name: &'static str,
    pub description: &'static str,
    pub example: JsonValue,
}

/// Metadata about query strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyMetadata {
    /// The strategy name as used in QueryStrategy enum
    pub name: &'static str,
    /// Human-readable description
    pub description: &'static str,
    /// When to use this strategy
    pub usage_guidance: &'static str,
    /// Query types commonly used with this strategy
    pub common_queries: Vec<&'static str>,
    /// Example scenario
    pub example_scenario: &'static str,
}

impl QueryRegistry {
    /// Get all available query types with their metadata
    pub fn get_all_query_types() -> Vec<QueryTypeMetadata> {
        vec![
            // Entity-focused queries
            QueryTypeMetadata {
                name: "EntityEvents",
                description: "Retrieve all events involving specific entities",
                usage_guidance: "Use when you need to understand what happened to or was done by specific characters/entities",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "entity_names",
                        type_name: "Vec<String>",
                        description: "List of entity names to query events for",
                        example: serde_json::json!(["Alice", "Bob"]),
                    },
                ],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "time_scope",
                        type_name: "String",
                        description: "Time range to search: 'recent', 'all', or specific date range",
                        example: serde_json::json!("recent"),
                    },
                    ParameterMetadata {
                        name: "max_results",
                        type_name: "u32",
                        description: "Maximum number of events to return",
                        example: serde_json::json!(20),
                    },
                ],
                returns: "List of events with timestamps, descriptions, and involved entities",
                example: "Get all events involving Alice and Bob in the last 24 hours",
                dependencies: vec![],
                typical_tokens: 500,
            },
            QueryTypeMetadata {
                name: "EntityCurrentState",
                description: "Get the current state/status of entities",
                usage_guidance: "Use when you need to know the present condition, location, or attributes of entities",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "entity_names",
                        type_name: "Vec<String>",
                        description: "List of entity names to get current state for",
                        example: serde_json::json!(["Alice"]),
                    },
                ],
                optional_parameters: vec![],
                returns: "Current attributes, location, health, inventory, and other state information",
                example: "Get Alice's current location, health, and inventory",
                dependencies: vec![],
                typical_tokens: 300,
            },
            QueryTypeMetadata {
                name: "EntityStates",
                description: "Get historical state changes for entities",
                usage_guidance: "Use when you need to track how entities have changed over time",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "entity_names",
                        type_name: "Vec<String>",
                        description: "List of entity names to track state changes for",
                        example: serde_json::json!(["Alice"]),
                    },
                ],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "time_scope",
                        type_name: "String",
                        description: "Time range to search state changes",
                        example: serde_json::json!("recent"),
                    },
                ],
                returns: "Timeline of state changes with before/after values",
                example: "Track how Alice's health and location changed over the last week",
                dependencies: vec![],
                typical_tokens: 400,
            },
            QueryTypeMetadata {
                name: "ActiveEntities",
                description: "Find entities that are currently active or relevant",
                usage_guidance: "Use when you need to know who is present or participating in the current scene",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "location_name",
                        type_name: "String",
                        description: "Filter by specific location",
                        example: serde_json::json!("Town Square"),
                    },
                    ParameterMetadata {
                        name: "time_scope",
                        type_name: "String",
                        description: "Define what counts as 'active' (e.g., last hour)",
                        example: serde_json::json!("recent"),
                    },
                ],
                returns: "List of currently active entities with their recent activity",
                example: "Find all entities active in the Town Square right now",
                dependencies: vec![],
                typical_tokens: 350,
            },
            
            // Relationship queries
            QueryTypeMetadata {
                name: "EntityRelationships",
                description: "Get relationships between entities",
                usage_guidance: "Use when you need to understand social dynamics, alliances, or connections",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "entity_names",
                        type_name: "Vec<String>",
                        description: "Entities to find relationships for",
                        example: serde_json::json!(["Alice", "Bob"]),
                    },
                ],
                optional_parameters: vec![],
                returns: "Relationship types, strength, history, and current status",
                example: "Get all relationships between Alice and other entities",
                dependencies: vec![],
                typical_tokens: 400,
            },
            QueryTypeMetadata {
                name: "SharedEvents",
                description: "Find events involving multiple specific entities",
                usage_guidance: "Use when you need to understand shared history or interactions",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "entity_names",
                        type_name: "Vec<String>",
                        description: "All entities that must be involved",
                        example: serde_json::json!(["Alice", "Bob", "Charlie"]),
                    },
                ],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "time_scope",
                        type_name: "String",
                        description: "Time range to search",
                        example: serde_json::json!("all"),
                    },
                ],
                returns: "Events where all specified entities were involved",
                example: "Find all events where Alice, Bob, and Charlie were present",
                dependencies: vec!["EntityEvents"],
                typical_tokens: 450,
            },
            
            // Causal queries
            QueryTypeMetadata {
                name: "CausalChain",
                description: "Trace cause-and-effect relationships between events",
                usage_guidance: "Use when you need to understand how one event led to another",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "event_id",
                        type_name: "String",
                        description: "Starting event to trace from",
                        example: serde_json::json!("event_123"),
                    },
                    ParameterMetadata {
                        name: "entity_names",
                        type_name: "Vec<String>",
                        description: "Focus on causal chains involving these entities",
                        example: serde_json::json!(["Alice"]),
                    },
                    ParameterMetadata {
                        name: "max_depth",
                        type_name: "u32",
                        description: "Maximum causal links to follow",
                        example: serde_json::json!(5),
                    },
                ],
                returns: "Chain of events showing cause-and-effect relationships",
                example: "Trace what events were caused by Alice stealing the artifact",
                dependencies: vec!["EntityEvents"],
                typical_tokens: 600,
            },
            QueryTypeMetadata {
                name: "CausalFactors",
                description: "Find all factors that contributed to an event or state",
                usage_guidance: "Use when you need to understand why something happened",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "event_id",
                        type_name: "String",
                        description: "Event or state to analyze causes for",
                        example: serde_json::json!("event_456"),
                    },
                ],
                optional_parameters: vec![],
                returns: "All contributing factors, preconditions, and triggers",
                example: "What factors led to the kingdom falling into chaos?",
                dependencies: vec!["CausalChain"],
                typical_tokens: 500,
            },
            
            // Spatial queries
            QueryTypeMetadata {
                name: "SpatialEntities",
                description: "Find entities in specific locations",
                usage_guidance: "Use when you need to know who or what is in a particular place",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "location_name",
                        type_name: "String",
                        description: "Location to search",
                        example: serde_json::json!("Castle Throne Room"),
                    },
                ],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "include_contained",
                        type_name: "bool",
                        description: "Include entities in sub-locations",
                        example: serde_json::json!(true),
                    },
                    ParameterMetadata {
                        name: "time_scope",
                        type_name: "String",
                        description: "Time period to check",
                        example: serde_json::json!("current"),
                    },
                ],
                returns: "Entities present in the location with their positions",
                example: "Find all entities currently in the Castle Throne Room",
                dependencies: vec!["EntityCurrentState"],
                typical_tokens: 350,
            },
            
            // Temporal queries
            QueryTypeMetadata {
                name: "TimelineEvents",
                description: "Get chronological sequence of events",
                usage_guidance: "Use when you need to understand the order and timing of events",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "time_scope",
                        type_name: "String",
                        description: "Time range for the timeline",
                        example: serde_json::json!("recent"),
                    },
                    ParameterMetadata {
                        name: "entity_names",
                        type_name: "Vec<String>",
                        description: "Filter timeline to these entities",
                        example: serde_json::json!(["Alice", "Bob"]),
                    },
                ],
                returns: "Chronologically ordered list of events with timestamps",
                example: "Get timeline of all events in the last 24 hours",
                dependencies: vec![],
                typical_tokens: 500,
            },
            QueryTypeMetadata {
                name: "StateTransitions",
                description: "Find moments when entities changed state significantly",
                usage_guidance: "Use when you need to identify key turning points or changes",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "entity_names",
                        type_name: "Vec<String>",
                        description: "Entities to track transitions for",
                        example: serde_json::json!(["Alice"]),
                    },
                    ParameterMetadata {
                        name: "transition_type",
                        type_name: "String",
                        description: "Type of transition: health, location, relationship, etc.",
                        example: serde_json::json!("health"),
                    },
                ],
                returns: "Significant state changes with before/after comparisons",
                example: "Find all major health state changes for Alice",
                dependencies: vec!["EntityStates"],
                typical_tokens: 400,
            },
            QueryTypeMetadata {
                name: "RecentEvents",
                description: "Get the most recent events across the world",
                usage_guidance: "Use when you need current context or latest happenings",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "max_results",
                        type_name: "u32",
                        description: "Number of recent events to return",
                        example: serde_json::json!(10),
                    },
                ],
                returns: "Most recent events with timestamps and participants",
                example: "Get the 10 most recent events in the game world",
                dependencies: vec![],
                typical_tokens: 400,
            },
            
            // Advanced queries
            QueryTypeMetadata {
                name: "HistoricalParallels",
                description: "Find similar events or patterns from the past",
                usage_guidance: "Use when you want to find precedents or predict outcomes based on history",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "search_pattern",
                        type_name: "String",
                        description: "Pattern or event type to find parallels for",
                        example: serde_json::json!("betrayal of a trusted advisor"),
                    },
                ],
                optional_parameters: vec![],
                returns: "Similar historical events and their outcomes",
                example: "Find historical parallels to the current political crisis",
                dependencies: vec!["EntityEvents", "CausalChain"],
                typical_tokens: 600,
            },
            QueryTypeMetadata {
                name: "NarrativeThreads",
                description: "Identify ongoing story threads and plot lines",
                usage_guidance: "Use when you need to track narrative arcs or story continuity",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "entity_names",
                        type_name: "Vec<String>",
                        description: "Focus on threads involving these entities",
                        example: serde_json::json!(["Alice"]),
                    },
                ],
                returns: "Active narrative threads with their current status and key events",
                example: "Identify all active plot threads involving Alice",
                dependencies: vec!["EntityEvents", "CausalChain"],
                typical_tokens: 500,
            },
            
            // Chronicle queries
            QueryTypeMetadata {
                name: "ChronicleEvents",
                description: "Search chronicle records for specific events",
                usage_guidance: "Use when you need detailed historical records or lore",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "search_query",
                        type_name: "String",
                        description: "Text to search for in chronicles",
                        example: serde_json::json!("the great war"),
                    },
                    ParameterMetadata {
                        name: "chronicle_id",
                        type_name: "String",
                        description: "Specific chronicle to search",
                        example: serde_json::json!("chronicle_001"),
                    },
                ],
                returns: "Chronicle entries matching the search criteria",
                example: "Search chronicles for mentions of 'the great war'",
                dependencies: vec![],
                typical_tokens: 600,
            },
            QueryTypeMetadata {
                name: "ChronicleTimeline",
                description: "Get timeline from chronicle records",
                usage_guidance: "Use when you need historical chronology from written records",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "chronicle_id",
                        type_name: "String",
                        description: "Chronicle to extract timeline from",
                        example: serde_json::json!("chronicle_001"),
                    },
                ],
                optional_parameters: vec![],
                returns: "Chronological events extracted from chronicle text",
                example: "Extract timeline from the Royal Chronicles",
                dependencies: vec!["ChronicleEvents"],
                typical_tokens: 500,
            },
            QueryTypeMetadata {
                name: "ChronicleThemes",
                description: "Extract themes and topics from chronicles",
                usage_guidance: "Use when you need to understand recurring themes or topics in historical records",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "chronicle_id",
                        type_name: "String",
                        description: "Specific chronicle to analyze",
                        example: serde_json::json!("chronicle_001"),
                    },
                ],
                returns: "Major themes, topics, and their prevalence in chronicles",
                example: "Identify major themes in the War Chronicles",
                dependencies: vec!["ChronicleEvents"],
                typical_tokens: 400,
            },
            QueryTypeMetadata {
                name: "RelatedChronicles",
                description: "Find chronicles related to specific topics or events",
                usage_guidance: "Use when you need to find all historical records about something",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "search_query",
                        type_name: "String",
                        description: "Topic to find related chronicles for",
                        example: serde_json::json!("dragon attacks"),
                    },
                ],
                optional_parameters: vec![],
                returns: "List of chronicles that mention or relate to the topic",
                example: "Find all chronicles mentioning dragon attacks",
                dependencies: vec![],
                typical_tokens: 350,
            },
            
            // Lorebook queries
            QueryTypeMetadata {
                name: "LorebookEntries",
                description: "Search lorebook for specific information",
                usage_guidance: "Use when you need world lore, rules, or background information",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "search_query",
                        type_name: "String",
                        description: "Text to search for in lorebook",
                        example: serde_json::json!("magic system"),
                    },
                    ParameterMetadata {
                        name: "entry_type",
                        type_name: "String",
                        description: "Type of entry: concept, location, character, etc.",
                        example: serde_json::json!("concept"),
                    },
                ],
                returns: "Lorebook entries with detailed information",
                example: "Search lorebook for information about the magic system",
                dependencies: vec![],
                typical_tokens: 500,
            },
            QueryTypeMetadata {
                name: "LorebookConcepts",
                description: "Get conceptual information from lorebook",
                usage_guidance: "Use when you need to understand world concepts, rules, or systems",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "concept_type",
                        type_name: "String",
                        description: "Type of concept: magic, politics, culture, etc.",
                        example: serde_json::json!("magic"),
                    },
                ],
                optional_parameters: vec![],
                returns: "Detailed explanations of world concepts",
                example: "Get all lorebook information about magic concepts",
                dependencies: vec!["LorebookEntries"],
                typical_tokens: 600,
            },
            QueryTypeMetadata {
                name: "LorebookCharacters",
                description: "Get character information from lorebook",
                usage_guidance: "Use when you need background on important characters",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "character_name",
                        type_name: "String",
                        description: "Specific character to look up",
                        example: serde_json::json!("King Arthur"),
                    },
                ],
                returns: "Character backgrounds, histories, and significance",
                example: "Get lorebook entry for King Arthur",
                dependencies: vec!["LorebookEntries"],
                typical_tokens: 400,
            },
            QueryTypeMetadata {
                name: "LorebookLocations",
                description: "Get location information from lorebook",
                usage_guidance: "Use when you need details about places in the world",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "location_name",
                        type_name: "String",
                        description: "Specific location to look up",
                        example: serde_json::json!("Crystal Caverns"),
                    },
                ],
                returns: "Location descriptions, history, and significance",
                example: "Get lorebook information about the Crystal Caverns",
                dependencies: vec!["LorebookEntries"],
                typical_tokens: 400,
            },
            QueryTypeMetadata {
                name: "LorebookContext",
                description: "Get contextual lore relevant to current situation",
                usage_guidance: "Use when you need background information relevant to the current narrative",
                required_parameters: vec![
                    ParameterMetadata {
                        name: "context_keywords",
                        type_name: "Vec<String>",
                        description: "Keywords describing the current context",
                        example: serde_json::json!(["dragon", "mountain", "prophecy"]),
                    },
                ],
                optional_parameters: vec![],
                returns: "Relevant lore entries that provide context",
                example: "Get lore context for a scene involving dragons and prophecy",
                dependencies: vec!["LorebookEntries"],
                typical_tokens: 500,
            },
            
            // Meta queries
            QueryTypeMetadata {
                name: "MissingEntities",
                description: "Identify entities referenced but not found in the system",
                usage_guidance: "Use when you need to handle references to unknown entities",
                required_parameters: vec![],
                optional_parameters: vec![
                    ParameterMetadata {
                        name: "search_context",
                        type_name: "String",
                        description: "Context to search for missing entity references",
                        example: serde_json::json!("recent_events"),
                    },
                ],
                returns: "List of entity names that are referenced but don't exist",
                example: "Find all entity references that don't have corresponding records",
                dependencies: vec![],
                typical_tokens: 300,
            },
        ]
    }
    
    /// Get all available query strategies with their metadata
    pub fn get_all_strategies() -> Vec<StrategyMetadata> {
        vec![
            StrategyMetadata {
                name: "CausalChainTraversal",
                description: "Follow cause-and-effect relationships to understand how events unfold",
                usage_guidance: "Use when the user asks 'why' or 'what caused' questions, or needs to understand consequences",
                common_queries: vec!["CausalChain", "CausalFactors", "EntityEvents", "StateTransitions"],
                example_scenario: "User asks: 'Why did the kingdom fall?' - traces back through causal events",
            },
            StrategyMetadata {
                name: "SpatialContextMapping",
                description: "Build understanding based on location and spatial relationships",
                usage_guidance: "Use when location is important or user asks about 'where' or 'who is nearby'",
                common_queries: vec!["SpatialEntities", "EntityCurrentState", "ActiveEntities"],
                example_scenario: "User asks: 'Who is in the throne room?' - maps spatial context",
            },
            StrategyMetadata {
                name: "RelationshipNetworkTraversal",
                description: "Explore social connections and relationship dynamics",
                usage_guidance: "Use for questions about alliances, conflicts, or social dynamics",
                common_queries: vec!["EntityRelationships", "SharedEvents", "EntityEvents"],
                example_scenario: "User asks: 'Who are Alice's allies?' - traverses relationship network",
            },
            StrategyMetadata {
                name: "TemporalStateReconstruction",
                description: "Rebuild state at specific time points or track changes over time",
                usage_guidance: "Use when user asks about past states or how things have changed",
                common_queries: vec!["EntityStates", "StateTransitions", "TimelineEvents"],
                example_scenario: "User asks: 'What was the city like before the war?' - reconstructs past state",
            },
            StrategyMetadata {
                name: "CausalProjection",
                description: "Project likely future outcomes based on current state and patterns",
                usage_guidance: "Use when user asks 'what will happen' or 'what if' questions",
                common_queries: vec!["CausalChain", "HistoricalParallels", "EntityCurrentState"],
                example_scenario: "User asks: 'What might happen if Alice confronts Bob?' - projects outcomes",
            },
            StrategyMetadata {
                name: "NarrativeContextAssembly",
                description: "Build comprehensive narrative context for storytelling",
                usage_guidance: "Use when crafting responses that need rich narrative detail",
                common_queries: vec!["NarrativeThreads", "EntityEvents", "RecentEvents", "EntityCurrentState"],
                example_scenario: "User asks for a story update - assembles full narrative context",
            },
            StrategyMetadata {
                name: "StateSnapshot",
                description: "Capture complete current state efficiently",
                usage_guidance: "Use when you need a quick overview of the present moment",
                common_queries: vec!["EntityCurrentState", "ActiveEntities", "RecentEvents"],
                example_scenario: "User asks: 'What's happening right now?' - takes state snapshot",
            },
            StrategyMetadata {
                name: "ComparativeAnalysis",
                description: "Compare different entities, time periods, or situations",
                usage_guidance: "Use when user asks for comparisons or contrasts",
                common_queries: vec!["EntityStates", "HistoricalParallels", "SharedEvents"],
                example_scenario: "User asks: 'How is Alice different from before?' - compares states",
            },
            StrategyMetadata {
                name: "ChronicleNarrativeMapping",
                description: "Connect current events to historical chronicle records",
                usage_guidance: "Use when historical context from chronicles is important",
                common_queries: vec!["ChronicleEvents", "ChronicleTimeline", "RelatedChronicles"],
                example_scenario: "User references historical event - maps to chronicle records",
            },
            StrategyMetadata {
                name: "ChronicleThematicAnalysis",
                description: "Analyze themes and patterns across chronicle records",
                usage_guidance: "Use when looking for recurring themes or patterns in history",
                common_queries: vec!["ChronicleThemes", "ChronicleEvents", "HistoricalParallels"],
                example_scenario: "User asks: 'Have we seen this before?' - analyzes chronicle themes",
            },
            StrategyMetadata {
                name: "ChronicleTimelineReconstruction",
                description: "Build detailed timeline from chronicle records",
                usage_guidance: "Use when precise historical chronology is needed",
                common_queries: vec!["ChronicleTimeline", "ChronicleEvents", "TimelineEvents"],
                example_scenario: "User asks: 'What's the history of this conflict?' - reconstructs timeline",
            },
            StrategyMetadata {
                name: "LorebookContextualRetrieval",
                description: "Retrieve relevant lore for the current situation",
                usage_guidance: "Use when world lore or background information enhances understanding",
                common_queries: vec!["LorebookContext", "LorebookEntries", "LorebookConcepts"],
                example_scenario: "User encounters magic - retrieves relevant lore about magic system",
            },
            StrategyMetadata {
                name: "LorebookConceptualMapping",
                description: "Map current situation to lorebook concepts and rules",
                usage_guidance: "Use when understanding world rules or concepts is important",
                common_queries: vec!["LorebookConcepts", "LorebookEntries", "LorebookContext"],
                example_scenario: "User asks: 'How does magic work?' - maps to lorebook concepts",
            },
            StrategyMetadata {
                name: "LorebookCulturalContext",
                description: "Provide cultural and societal context from lorebook",
                usage_guidance: "Use when cultural understanding enhances the narrative",
                common_queries: vec!["LorebookContext", "LorebookLocations", "LorebookCharacters"],
                example_scenario: "User enters new region - provides cultural context",
            },
            StrategyMetadata {
                name: "AdaptiveNarrativeStrategy",
                description: "Dynamically adapt strategy based on narrative needs",
                usage_guidance: "Use when the optimal approach isn't clear or needs flexibility",
                common_queries: vec!["EntityEvents", "NarrativeThreads", "EntityCurrentState", "RecentEvents"],
                example_scenario: "Complex user question - adapts strategy as understanding develops",
            },
            StrategyMetadata {
                name: "EmergentPatternDiscovery",
                description: "Discover hidden patterns and connections in data",
                usage_guidance: "Use when looking for non-obvious relationships or patterns",
                common_queries: vec!["HistoricalParallels", "NarrativeThreads", "CausalChain"],
                example_scenario: "User asks: 'Is there a pattern here?' - discovers emergent patterns",
            },
            StrategyMetadata {
                name: "ContextualRelevanceOptimization",
                description: "Optimize query selection for maximum relevance with minimal tokens",
                usage_guidance: "Use when token budget is tight or efficiency is critical",
                common_queries: vec!["EntityCurrentState", "RecentEvents", "ActiveEntities"],
                example_scenario: "Limited token budget - optimizes for most relevant context",
            },
        ]
    }
    
    /// Generate a formatted string explaining all query types for AI consumption
    pub fn generate_query_type_reference() -> String {
        let mut output = String::from("AVAILABLE QUERY TYPES - Complete Reference:\n\n");
        
        for query_type in Self::get_all_query_types() {
            output.push_str(&format!("{}:\n", query_type.name));
            output.push_str(&format!("  Description: {}\n", query_type.description));
            output.push_str(&format!("  When to use: {}\n", query_type.usage_guidance));
            output.push_str(&format!("  Returns: {}\n", query_type.returns));
            
            if !query_type.required_parameters.is_empty() {
                output.push_str("  Required parameters:\n");
                for param in &query_type.required_parameters {
                    output.push_str(&format!("    - {} ({}): {}\n", param.name, param.type_name, param.description));
                }
            }
            
            if !query_type.optional_parameters.is_empty() {
                output.push_str("  Optional parameters:\n");
                for param in &query_type.optional_parameters {
                    output.push_str(&format!("    - {} ({}): {}\n", param.name, param.type_name, param.description));
                }
            }
            
            output.push_str(&format!("  Example: {}\n", query_type.example));
            output.push_str(&format!("  Typical tokens: {}\n\n", query_type.typical_tokens));
        }
        
        output
    }
    
    /// Generate a formatted string explaining all strategies for AI consumption
    pub fn generate_strategy_reference() -> String {
        let mut output = String::from("\nAVAILABLE STRATEGIES - Complete Reference:\n\n");
        
        for strategy in Self::get_all_strategies() {
            output.push_str(&format!("{}:\n", strategy.name));
            output.push_str(&format!("  Description: {}\n", strategy.description));
            output.push_str(&format!("  When to use: {}\n", strategy.usage_guidance));
            output.push_str(&format!("  Common queries: {}\n", strategy.common_queries.join(", ")));
            output.push_str(&format!("  Example: {}\n\n", strategy.example_scenario));
        }
        
        output
    }
    
    /// Get just the query type names (for JSON schema enums)
    pub fn get_query_type_names() -> Vec<&'static str> {
        Self::get_all_query_types()
            .iter()
            .map(|qt| qt.name)
            .collect()
    }
    
    /// Get just the strategy names (for JSON schema enums)
    pub fn get_strategy_names() -> Vec<&'static str> {
        Self::get_all_strategies()
            .iter()
            .map(|s| s.name)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_query_registry_completeness() {
        let query_types = QueryRegistry::get_all_query_types();
        assert_eq!(query_types.len(), 24); // Should have all 24 query types
        
        let strategies = QueryRegistry::get_all_strategies();
        assert_eq!(strategies.len(), 17); // Should have all 17 strategies
    }
    
    #[test]
    fn test_reference_generation() {
        let query_ref = QueryRegistry::generate_query_type_reference();
        assert!(query_ref.contains("EntityEvents"));
        assert!(query_ref.contains("Required parameters"));
        
        let strategy_ref = QueryRegistry::generate_strategy_reference();
        assert!(strategy_ref.contains("CausalChainTraversal"));
        assert!(strategy_ref.contains("When to use"));
    }
}