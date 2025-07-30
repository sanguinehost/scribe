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
// pub mod narrative_tools; // Removed - broken legacy module
pub mod entity_resolution_tool;
pub mod factory;
pub mod tools;
pub mod persona_context;
pub mod tactical_agent;
pub mod perception_agent;
pub mod strategic_agent;
pub mod hierarchical_pipeline;
pub mod lightning_agent;
pub mod orchestrator;
pub mod performance_analyzer;
pub mod strategic_structured_output;
pub mod tactical_structured_output;
pub mod tactical_planning_structured_output;
pub mod perception_structured_output;
pub mod entity_dependency_structured_output;
pub mod event_participants_structured_output;
pub mod query_relevance_structured_output;
pub mod historical_state_reconstruction_structured_output;
pub mod event_significance_structured_output;
pub mod narrative_answer_generation_structured_output;
pub mod intelligent_world_state_planner;
pub mod types;
pub mod unified_tool_registry;
pub mod ai_tool_discovery;
pub mod tool_initialization;
pub mod shared_context;
pub mod executor;


// Re-export key types for convenience
pub use agent_runner::{NarrativeAgentRunner, NarrativeWorkflowConfig, TriageResult, ActionPlan, PlannedAction, UserPersonaContext};
pub use factory::AgenticNarrativeFactory;
pub use tools::{ScribeTool, ToolError, ToolParams, ToolResult};
// pub use narrative_tools::{ ... }; // Removed - broken legacy module
pub use entity_resolution_tool::{EntityResolutionTool, ProcessingMode};
pub use tactical_agent::TacticalAgent;
pub use perception_agent::{PerceptionAgent, PerceptionContext, PerceptionResult};
pub use strategic_agent::StrategicAgent;
pub use hierarchical_pipeline::{
    HierarchicalAgentPipeline, HierarchicalPipelineConfig, 
    HierarchicalPipelineResult, PipelineMetrics
};
pub use orchestrator::{WorkflowOrchestrator, OrchestratorState, StageResults};
pub use strategic_structured_output::*;
pub use tactical_structured_output::*;
pub use tool_initialization::initialize_all_tools;
pub use shared_context::{SharedAgentContext, ContextEntry, ContextType, AgentType, ContextQuery, AgentWithSharedContext};