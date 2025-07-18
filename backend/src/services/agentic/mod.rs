//! # Agentic Services
//!
//! This module contains the core components for building and managing AI agents
//! that can use tools to interact with the Scribe application. It is designed
//! around the "Everything as a Tool" principle, where all application logic
//! is encapsulated within self-contained, discoverable tools.
//!
//! ## Key Components:
//!
//! *   **`tools`**: Defines the `ScribeTool` trait, the fundamental interface for all
//!     tools that an agent can use.
//! *   **`registry`**: Provides the `ToolRegistry`, a central place to store and
//!     access all implemented tools.
//! *   **`narrative_tools`**: Implementations of specific tools for chronicle and
//!     lorebook management.

pub mod agent_runner;
pub mod narrative_tools;
pub mod entity_resolution_tool;
pub mod factory;
pub mod registry;
pub mod tools;
pub mod persona_context;
pub mod tactical_agent;
pub mod perception_agent;
pub mod strategic_agent;
pub mod hierarchical_pipeline;
pub mod strategic_structured_output;
pub mod tactical_structured_output;
pub mod perception_structured_output;
pub mod entity_dependency_structured_output;
pub mod event_participants_structured_output;
pub mod query_relevance_structured_output;
pub mod historical_state_reconstruction_structured_output;
pub mod event_significance_structured_output;
pub mod relationship_analysis_structured_output;
pub mod narrative_answer_generation_structured_output;
pub mod types;


// Re-export key types for convenience
pub use agent_runner::{NarrativeAgentRunner, NarrativeWorkflowConfig, TriageResult, ActionPlan, PlannedAction, UserPersonaContext};
pub use factory::AgenticNarrativeFactory;
pub use registry::ToolRegistry;
pub use tools::{ScribeTool, ToolError, ToolParams, ToolResult};
pub use narrative_tools::{
    CreateChronicleEventTool, CreateLorebookEntryTool, 
    AnalyzeTextSignificanceTool, ExtractTemporalEventsTool, ExtractWorldConceptsTool,
    SearchKnowledgeBaseTool, UpdateLorebookEntryTool
};
pub use entity_resolution_tool::{EntityResolutionTool, ProcessingMode};
pub use tactical_agent::TacticalAgent;
pub use perception_agent::{PerceptionAgent, PerceptionContext, PerceptionResult};
pub use strategic_agent::StrategicAgent;
pub use hierarchical_pipeline::{
    HierarchicalAgentPipeline, HierarchicalPipelineConfig, 
    HierarchicalPipelineResult, PipelineMetrics
};
pub use strategic_structured_output::*;
pub use tactical_structured_output::*;