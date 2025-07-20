//! Tool Access Configuration
//! 
//! This module defines the default access policies for tools based on agent types.
//! It implements the Hierarchical Agent Framework:
//! - Strategic Layer ("Director"): High-level narrative planning and thematic analysis
//! - Tactical Layer ("Stage Manager"): Bridges strategy and execution, decomposes directives
//! - Perception Layer ("World State Observer"): Processes AI responses, updates world state

use super::tool_registry::{AgentType, ToolAccessPolicy};

/// Define the default tool access policies for each agent type
pub fn get_default_tool_policies() -> Vec<(&'static str, ToolAccessPolicy)> {
    vec![
        // ========== High-Level Analysis Tools ==========
        ("analyze_text_significance", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Strategic, AgentType::Orchestrator],
            priority: 10,
            required: true,
        }),
        ("extract_world_concepts", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Strategic, AgentType::Orchestrator],
            priority: 9,
            required: false,
        }),
        ("analyze_hierarchy_request", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Strategic],
            priority: 7,
            required: false,
        }),
        
        // ========== Entity Query Tools ==========
        ("find_entity", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Tactical, AgentType::Perception, AgentType::Orchestrator],
            priority: 10,
            required: true,
        }),
        ("get_spatial_context", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Tactical],
            priority: 10,
            required: true,
        }),
        ("get_entity_details", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Tactical],
            priority: 9,
            required: false,
        }),
        ("get_entity_hierarchy", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Tactical],
            priority: 8,
            required: false,
        }),
        
        // ========== Entity Management Tools ==========
        ("create_entity", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Perception, AgentType::Orchestrator],
            priority: 10,
            required: true,
        }),
        ("update_entity", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Perception],
            priority: 10,
            required: true,
        }),
        ("update_relationship", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Perception],
            priority: 9,
            required: true,
        }),
        ("update_salience", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Perception],
            priority: 8,
            required: false,
        }),
        
        // ========== AI Analysis Tools ==========
        ("resolve_entities", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Tactical, AgentType::Perception],
            priority: 8,
            required: false,
        }),
        
        // ========== Knowledge Management Tools ==========
        ("search_knowledge_base", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Strategic, AgentType::Tactical, AgentType::Perception, AgentType::Orchestrator],
            priority: 8,
            required: false,
        }),
        ("create_chronicle_event", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Perception],
            priority: 7,
            required: false,
        }),
        ("create_lorebook_entry", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Perception],
            priority: 5,
            required: false,
        }),
        
        // ========== Temporal Analysis Tools ==========
        ("extract_temporal_events", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Tactical, AgentType::Perception],
            priority: 6,
            required: false,
        }),
        
        // ========== Hierarchy Management Tools ==========
        ("promote_entity_hierarchy", ToolAccessPolicy {
            allowed_agents: vec![AgentType::Tactical, AgentType::Perception],
            priority: 6,
            required: false,
        }),
    ]
}

/// Get recommended tool usage patterns for each agent type
pub fn get_agent_tool_recommendations(agent_type: AgentType) -> &'static str {
    match agent_type {
        AgentType::Strategic => r#"
STRATEGIC LAYER ("DIRECTOR") TOOL USAGE GUIDE:
- You are the high-level narrative intelligence, thinking in chapters and acts
- Use 'analyze_text_significance' to identify major plot points and themes
- Use 'extract_world_concepts' to understand world-building and setting evolution
- Use 'analyze_hierarchy_request' to understand narrative structure needs
- Query 'search_knowledge_base' for long-term narrative consistency
- Generate strategic directives like "Execute Confrontation Scene" or "Deepen Character Development"
- DO NOT directly manipulate entities - your role is narrative direction
"#,
        
        AgentType::Tactical => r#"
TACTICAL LAYER ("STAGE MANAGER") TOOL USAGE GUIDE:
- You bridge strategic directives and concrete execution
- Decompose high-level directives into verifiable, actionable steps
- Use 'find_entity' and 'get_entity_details' to gather execution context
- Use 'get_spatial_context' to understand scene geography
- Use 'get_entity_hierarchy' for complex spatial relationships
- Use 'resolve_entities' when entity references are ambiguous
- Use 'extract_temporal_events' to maintain timeline consistency
- Create detailed plans that the Operational Layer can execute
"#,
        
        AgentType::Perception => r#"
PERCEPTION LAYER ("WORLD STATE OBSERVER") TOOL USAGE GUIDE:
- You process AI responses and maintain world state consistency
- Analyze narrative text to extract state changes and implications
- Use 'find_entity' before creating to prevent duplicates
- Use 'create_entity' for new characters, objects, and locations
- Use 'update_entity' to reflect all state changes from the narrative
- Use 'update_relationship' to track evolving connections
- Use 'update_salience' to mark narrative importance
- Use 'resolve_entities' to handle ambiguous references
- Create chronicle events and lorebook entries for significant moments
- Extract temporal events to maintain the timeline
"#,
        
        AgentType::Orchestrator => r#"
ORCHESTRATOR TOOL USAGE GUIDE:
- You coordinate the entire hierarchical agent system
- Use 'analyze_text_significance' for initial message triage
- Direct work to appropriate agent layers based on needs
- Use 'find_entity' and 'create_entity' for system-level operations
- Monitor overall narrative coherence and system performance
- Ensure efficient tool usage across all layers
- Handle edge cases that don't fit the standard hierarchy
"#,
    }
}

/// Validate that an agent is using tools appropriately
pub fn validate_tool_usage(agent_type: AgentType, tool_name: &str) -> Result<(), String> {
    match (agent_type, tool_name) {
        // Strategic Layer should not directly modify world state
        (AgentType::Strategic, "create_entity") |
        (AgentType::Strategic, "update_entity") |
        (AgentType::Strategic, "update_relationship") |
        (AgentType::Strategic, "update_salience") => {
            Err(format!(
                "Strategic Layer (Director) should not directly modify entities. \
                Strategic agents generate narrative directives, not world state changes."
            ))
        },
        
        // Strategic Layer should not query entity details
        (AgentType::Strategic, "find_entity") |
        (AgentType::Strategic, "get_entity_details") |
        (AgentType::Strategic, "get_spatial_context") => {
            Err(format!(
                "Strategic Layer (Director) should not query specific entities. \
                Focus on high-level narrative analysis and thematic understanding."
            ))
        },
        
        // Tactical Layer should not modify entities directly
        (AgentType::Tactical, "create_entity") |
        (AgentType::Tactical, "update_entity") |
        (AgentType::Tactical, "update_relationship") |
        (AgentType::Tactical, "update_salience") => {
            Err(format!(
                "Tactical Layer (Stage Manager) should not modify entities. \
                Tactical agents create plans for the Perception Layer to execute."
            ))
        },
        
        // Perception Layer should not do strategic analysis
        (AgentType::Perception, "analyze_hierarchy_request") => {
            Err(format!(
                "Perception Layer (World State Observer) should not perform strategic analysis. \
                Focus on processing AI responses and updating world state."
            ))
        },
        
        // All other combinations are allowed
        _ => Ok(()),
    }
}