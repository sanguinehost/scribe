//! Prompt Engineering Framework
//!
//! This module implements Phase 3.2.1 of the ECS Architecture Plan:
//! - Structured prompt templates for different reasoning types
//! - LLM-optimized context formatting
//! - Reasoning guidance and methodology suggestions
//! - Token-efficient representations for various query types
//!
//! Key Features:
//! - Template-based prompt generation for consistent structure
//! - Context-aware formatting based on query intent
//! - Reasoning methodology guidance for different analysis types
//! - Optimized for clarity and LLM comprehension

use crate::models::world_model::*;
use crate::services::nlp_query_handler::IntentType;

/// Prompt template engine for generating structured LLM prompts
pub struct PromptTemplates;

impl PromptTemplates {
    /// Generate a prompt for causal reasoning analysis
    pub fn causal_reasoning_prompt(context: &LLMWorldContext, query: &str) -> String {
        format!(
            r#"You are analyzing a narrative world with the following context:

## Current World State
{}

## Causal Chains Identified
{}

## Recent World Changes
{}

## Your Task
Answer the following question using causal reasoning: "{}"

## Reasoning Guidelines
1. **Trace Causality**: Follow the causal chains to identify root causes and their effects
2. **Consider Timing**: Pay attention to the sequence and timing of events
3. **Assess Confidence**: Note the confidence levels in causal relationships
4. **Multiple Paths**: Consider both direct and indirect causal pathways
5. **Evidence Base**: Reference specific events, entities, and relationships by name
6. **Uncertainty**: Acknowledge gaps or uncertainty in the causal chain

## Response Format
Provide a clear narrative explanation that:
- **Primary Cause(s)**: Identifies the most likely root cause(s)
- **Causal Chain**: Explains the step-by-step progression from cause to effect
- **Supporting Evidence**: References specific events and entities
- **Alternative Explanations**: Notes any other plausible causal paths
- **Confidence Assessment**: Rates confidence in the conclusion (High/Medium/Low)

Focus on creating a coherent narrative that explains the causal relationships clearly."#,
            Self::format_entity_summaries(&context.entity_summaries),
            Self::format_causal_chains(&context.causal_chains),
            Self::format_recent_changes(&context.recent_changes),
            query
        )
    }
    
    /// Generate a prompt for relationship analysis
    pub fn relationship_analysis_prompt(context: &LLMWorldContext, query: &str) -> String {
        format!(
            r#"You are analyzing relationships in a narrative world:

## Entity Overview
{}

## Relationship Network
{}

## Recent Relationship Changes
{}

## Spatial Context
{}

## Your Task
Answer the following relationship question: "{}"

## Analysis Framework
1. **Relationship Mapping**: Identify all relevant relationships and their types
2. **Strength Assessment**: Analyze relationship strength, trust, and dynamics
3. **Historical Context**: Consider how relationships have evolved over time
4. **Impact Analysis**: Examine how recent events affected these relationships
5. **Network Effects**: Look for relationship clusters and indirect influences
6. **Future Implications**: Consider how current relationship dynamics might evolve

## Response Format
Provide a comprehensive relationship analysis that includes:
- **Current Status**: Present state of the relationships in question
- **Relationship Dynamics**: Strength, type, and key characteristics
- **Historical Development**: How these relationships formed and changed
- **Influencing Factors**: Events, actions, or circumstances that shaped the relationships
- **Network Context**: How these relationships fit into the broader social network
- **Future Outlook**: Likely trajectory and potential changes

Emphasize the human/character elements and emotional dynamics where relevant."#,
            Self::format_entity_summaries(&context.entity_summaries),
            Self::format_relationship_graph(&context.relationship_graph),
            Self::format_recent_changes(&context.recent_changes),
            Self::format_spatial_context(&context.spatial_context),
            query
        )
    }
    
    /// Generate a prompt for temporal/timeline analysis
    pub fn temporal_analysis_prompt(context: &LLMWorldContext, query: &str) -> String {
        format!(
            r#"You are reconstructing a timeline of events in a narrative world:

## Entities Involved
{}

## Event Sequence
{}

## Causal Relationships
{}

## Recent Changes
{}

## Your Task
Answer the following temporal question: "{}"

## Timeline Analysis Guidelines
1. **Chronological Order**: Establish the sequence of events in time
2. **Causal Dependencies**: Identify which events caused or enabled others
3. **Entity State Changes**: Track how entities changed over time
4. **Critical Moments**: Highlight key turning points or decisive events
5. **Patterns**: Look for recurring themes or cyclical patterns
6. **Context**: Consider the broader circumstances surrounding each event

## Response Format
Provide a clear temporal analysis that includes:
- **Timeline Overview**: High-level sequence of major events
- **Detailed Progression**: Step-by-step breakdown of the relevant time period
- **State Changes**: How entities and situations evolved
- **Causal Connections**: How events influenced subsequent developments
- **Key Turning Points**: Moments that significantly altered the trajectory
- **Pattern Recognition**: Any recurring themes or predictable progressions

Present the timeline in a way that tells a coherent story of development and change."#,
            Self::format_entity_summaries(&context.entity_summaries),
            Self::format_causal_chains(&context.causal_chains),
            Self::format_causal_chains(&context.causal_chains), // Events as temporal sequence
            Self::format_recent_changes(&context.recent_changes),
            query
        )
    }
    
    /// Generate a prompt for spatial/location analysis
    pub fn spatial_analysis_prompt(context: &LLMWorldContext, query: &str) -> String {
        format!(
            r#"You are analyzing spatial relationships and locations in a narrative world:

## Entities and Their Locations
{}

## Spatial Hierarchy
{}

## Recent Movement and Changes
{}

## Your Task
Answer the following spatial question: "{}"

## Spatial Analysis Guidelines
1. **Location Mapping**: Identify where entities and events are positioned
2. **Spatial Relationships**: Understand proximity, containment, and adjacency
3. **Movement Patterns**: Track how entities move through space over time
4. **Strategic Significance**: Consider why locations matter for the narrative
5. **Accessibility**: Understand how geography affects interaction and travel
6. **Environmental Factors**: Consider how the physical environment influences events

## Response Format
Provide a spatial analysis that includes:
- **Location Overview**: Key places and their significance
- **Spatial Relationships**: How locations relate to each other geographically
- **Entity Positioning**: Where relevant entities are currently located
- **Movement Patterns**: How entities have moved or might move
- **Strategic Considerations**: Why spatial positioning matters
- **Environmental Impact**: How geography influences the situation

Focus on creating a clear mental map of the spatial situation."#,
            Self::format_entity_summaries(&context.entity_summaries),
            Self::format_spatial_context(&context.spatial_context),
            Self::format_recent_changes(&context.recent_changes),
            query
        )
    }
    
    /// Generate a prompt for quantitative analysis
    pub fn quantitative_analysis_prompt(context: &LLMWorldContext, query: &str) -> String {
        format!(
            r#"You are performing quantitative analysis of a narrative world:

## Entities and Their Attributes
{}

## Relationship Network Stats
{}

## Event Frequency and Patterns
{}

## Your Task
Answer the following quantitative question: "{}"

## Quantitative Analysis Guidelines
1. **Count and Measure**: Provide specific numbers where available
2. **Compare Quantities**: Analyze relative amounts and ratios
3. **Identify Patterns**: Look for statistical trends or distributions
4. **Assess Magnitude**: Determine if quantities are significant or unusual
5. **Temporal Trends**: Track how quantities change over time
6. **Uncertainty**: Acknowledge limitations in available data

## Response Format
Provide a quantitative analysis that includes:
- **Direct Counts**: Specific numbers answering the question
- **Comparative Analysis**: How quantities relate to each other
- **Statistical Insights**: Patterns, averages, or distributions
- **Confidence Level**: How reliable the numbers are
- **Context**: What these quantities mean in narrative terms
- **Trends**: How these numbers have changed or might change

Present numbers clearly and explain their significance to the story."#,
            Self::format_entity_summaries(&context.entity_summaries),
            Self::format_relationship_network_stats(&context.relationship_graph),
            Self::format_event_patterns(&context.causal_chains),
            query
        )
    }
    
    /// Generate a prompt for comparative analysis
    pub fn comparative_analysis_prompt(context: &LLMWorldContext, query: &str) -> String {
        format!(
            r#"You are comparing entities, situations, or concepts in a narrative world:

## Entities for Comparison
{}

## Relationship Dynamics
{}

## Historical Context
{}

## Your Task
Perform the following comparison: "{}"

## Comparative Analysis Framework
1. **Identify Comparison Points**: Determine relevant attributes to compare
2. **Gather Evidence**: Collect specific information about each subject
3. **Analyze Similarities**: Find common ground and shared characteristics
4. **Contrast Differences**: Highlight unique features and distinctions
5. **Assess Significance**: Determine which differences and similarities matter most
6. **Contextualize**: Consider how comparisons relate to the broader narrative

## Response Format
Provide a structured comparison that includes:
- **Comparison Overview**: Brief summary of what's being compared
- **Key Similarities**: Important common characteristics or patterns
- **Major Differences**: Significant distinctions and contrasts
- **Detailed Analysis**: Point-by-point comparison of relevant attributes
- **Relative Assessment**: Which entity/situation is "better" in various dimensions
- **Narrative Significance**: What these comparisons mean for the story

Use clear parallel structure to make comparisons easy to follow."#,
            Self::format_entity_summaries(&context.entity_summaries),
            Self::format_relationship_graph(&context.relationship_graph),
            Self::format_causal_chains(&context.causal_chains),
            query
        )
    }
    
    /// Generate a general inquiry prompt for open-ended questions
    pub fn general_inquiry_prompt(context: &LLMWorldContext, query: &str) -> String {
        format!(
            r#"You are analyzing a narrative world to answer a general question:

## Current World State
{}

## Key Relationships
{}

## Recent Developments
{}

## Available Context
{}

## Your Task
Answer the following question: "{}"

## General Analysis Guidelines
1. **Comprehensive Review**: Consider all relevant aspects of the world state
2. **Multiple Perspectives**: Look at the question from different angles
3. **Evidence-Based**: Ground your response in specific information from the context
4. **Narrative Coherence**: Ensure your answer fits the established world and story
5. **Balanced View**: Consider multiple interpretations or possibilities
6. **Clear Communication**: Present information in an organized, understandable way

## Response Format
Provide a thoughtful response that includes:
- **Direct Answer**: Clear response to the question asked
- **Supporting Evidence**: Specific information that supports your answer
- **Context Integration**: How your answer fits with the broader world state
- **Multiple Angles**: Different ways to interpret or approach the question
- **Implications**: What your answer might mean for future developments
- **Uncertainty**: Areas where information is incomplete or unclear

Focus on being helpful, accurate, and engaging while staying true to the narrative world."#,
            Self::format_entity_summaries(&context.entity_summaries),
            Self::format_relationship_graph(&context.relationship_graph),
            Self::format_recent_changes(&context.recent_changes),
            Self::format_reasoning_hints(&context.reasoning_hints),
            query
        )
    }
    
    /// Generate an appropriate prompt based on query intent type
    pub fn generate_prompt_for_intent(
        intent_type: &IntentType,
        context: &LLMWorldContext,
        query: &str,
    ) -> String {
        match intent_type {
            IntentType::CausalReasoning => Self::causal_reasoning_prompt(context, query),
            IntentType::RelationshipAnalysis => Self::relationship_analysis_prompt(context, query),
            IntentType::TemporalQuery => Self::temporal_analysis_prompt(context, query),
            IntentType::SpatialQuery => Self::spatial_analysis_prompt(context, query),
            IntentType::QuantitativeQuery => Self::quantitative_analysis_prompt(context, query),
            IntentType::ComparativeQuery => Self::comparative_analysis_prompt(context, query),
            IntentType::GeneralInquiry => Self::general_inquiry_prompt(context, query),
        }
    }
    
    // Helper formatting methods
    
    /// Format entity summaries for prompt inclusion
    fn format_entity_summaries(summaries: &[EntitySummary]) -> String {
        if summaries.is_empty() {
            return "No entities currently available in the context.".to_string();
        }
        
        summaries.iter()
            .map(|s| {
                let attributes = if s.key_attributes.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", 
                        s.key_attributes.iter()
                            .map(|(k, v)| format!("{}: {}", k, v))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                
                let recent_actions = if s.recent_actions.is_empty() {
                    String::new()
                } else {
                    format!(" (Recent: {})", s.recent_actions.join(", "))
                };
                
                format!("- **{}** ({}): {}{}{}", 
                    s.name, 
                    s.entity_type, 
                    s.current_state,
                    attributes,
                    recent_actions
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    /// Format causal chains for prompt inclusion
    fn format_causal_chains(chains: &[CausalChain]) -> String {
        if chains.is_empty() {
            return "No causal chains identified in the current context.".to_string();
        }
        
        chains.iter()
            .map(|c| {
                let steps = if c.steps.is_empty() {
                    " (direct causation)".to_string()
                } else {
                    format!(" via {} intermediate steps", c.steps.len())
                };
                
                format!("- **{}** → **{}** (confidence: {:.1}%){}", 
                    c.root_cause,
                    c.final_effect,
                    c.confidence * 100.0,
                    steps
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    /// Format relationship graph for prompt inclusion
    fn format_relationship_graph(graph: &RelationshipGraph) -> String {
        if graph.edges.is_empty() {
            return "No relationships currently mapped in the context.".to_string();
        }
        
        // Group relationships by type for better organization
        let mut relationships_by_type: std::collections::HashMap<String, Vec<&GraphEdge>> = 
            std::collections::HashMap::new();
        
        for edge in &graph.edges {
            relationships_by_type
                .entry(edge.relationship_type.clone())
                .or_insert_with(Vec::new)
                .push(edge);
        }
        
        let mut formatted = Vec::new();
        for (rel_type, edges) in relationships_by_type {
            formatted.push(format!("**{}:**", rel_type));
            for edge in edges {
                // Find node names for the edge
                let from_name = graph.nodes.iter()
                    .find(|n| n.entity_id == edge.from_entity)
                    .map(|n| n.label.as_str())
                    .unwrap_or("Unknown");
                    
                let to_name = graph.nodes.iter()
                    .find(|n| n.entity_id == edge.to_entity)
                    .map(|n| n.label.as_str())
                    .unwrap_or("Unknown");
                
                formatted.push(format!("  - {} → {} (strength: {:.1})", 
                    from_name, to_name, edge.strength));
            }
        }
        
        formatted.join("\n")
    }
    
    /// Format recent changes for prompt inclusion
    fn format_recent_changes(changes: &[RecentChange]) -> String {
        if changes.is_empty() {
            return "No recent changes recorded in the current time window.".to_string();
        }
        
        changes.iter()
            .map(|c| {
                let impact_indicator = match c.impact_level.as_str() {
                    "high" => "🔴 HIGH:",
                    "medium" => "🟡 MEDIUM:",
                    "low" => "🟢 LOW:",
                    _ => "❓ UNKNOWN:",
                };
                
                format!("- {} {} ({})", 
                    impact_indicator,
                    c.description,
                    c.change_type
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    /// Format spatial context for prompt inclusion
    fn format_spatial_context(spatial: &SpatialContext) -> String {
        if spatial.locations.is_empty() {
            return "No spatial information available in the current context.".to_string();
        }
        
        spatial.locations.iter()
            .map(|loc| {
                let entities = if loc.entities_present.is_empty() {
                    " (empty)".to_string()
                } else {
                    format!(" (contains: {})", loc.entities_present.join(", "))
                };
                
                format!("- **{}** ({}): {}{}", 
                    loc.name,
                    loc.location_type,
                    loc.description,
                    entities
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    /// Format reasoning hints for prompt inclusion
    fn format_reasoning_hints(hints: &[String]) -> String {
        if hints.is_empty() {
            return "No specific reasoning hints available.".to_string();
        }
        
        hints.iter()
            .enumerate()
            .map(|(i, hint)| format!("{}. {}", i + 1, hint))
            .collect::<Vec<_>>()
            .join("\n")
    }
    
    /// Format relationship network statistics
    fn format_relationship_network_stats(graph: &RelationshipGraph) -> String {
        let node_count = graph.nodes.len();
        let edge_count = graph.edges.len();
        let cluster_count = graph.clusters.len();
        
        if node_count == 0 {
            return "No relationship network data available.".to_string();
        }
        
        // Calculate some basic network statistics
        let avg_connections = if node_count > 0 {
            (edge_count * 2) as f32 / node_count as f32 // Each edge connects 2 nodes
        } else {
            0.0
        };
        
        let mut relationship_types: std::collections::HashMap<String, usize> = 
            std::collections::HashMap::new();
        for edge in &graph.edges {
            *relationship_types.entry(edge.relationship_type.clone()).or_insert(0) += 1;
        }
        
        let type_breakdown = relationship_types.iter()
            .map(|(rel_type, count)| format!("{}: {}", rel_type, count))
            .collect::<Vec<_>>()
            .join(", ");
        
        format!(
            "- **Network Size**: {} entities, {} relationships\n\
             - **Connectivity**: {:.1} average connections per entity\n\
             - **Clusters**: {} relationship clusters identified\n\
             - **Relationship Types**: {}",
            node_count, edge_count, avg_connections, cluster_count, type_breakdown
        )
    }
    
    /// Format event patterns from causal chains
    fn format_event_patterns(chains: &[CausalChain]) -> String {
        if chains.is_empty() {
            return "No event patterns available for analysis.".to_string();
        }
        
        let total_events = chains.iter().map(|c| c.steps.len()).sum::<usize>();
        let avg_chain_length = if !chains.is_empty() {
            total_events as f32 / chains.len() as f32
        } else {
            0.0
        };
        
        let high_confidence_chains = chains.iter()
            .filter(|c| c.confidence > 0.8)
            .count();
        
        format!(
            "- **Total Event Chains**: {}\n\
             - **Average Chain Length**: {:.1} steps\n\
             - **High Confidence Chains**: {} ({:.1}%)\n\
             - **Most Common Root Causes**: [Analysis would require more context]\n\
             - **Most Common Effects**: [Analysis would require more context]",
            chains.len(),
            avg_chain_length,
            high_confidence_chains,
            (high_confidence_chains as f32 / chains.len() as f32) * 100.0
        )
    }
}