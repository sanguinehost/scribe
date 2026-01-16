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
pub mod context_enrichment_agent;
pub mod factory;
pub mod narrative_tools;
pub mod persona_context;
pub mod registry;
pub mod state_manager_agent;
pub mod tools;

#[cfg(test)]
mod narrative_tools_tests;

// Re-export key types for convenience
pub use agent_runner::{NarrativeAgentRunner, NarrativeWorkflowConfig, NarrativeWorkflowResult};
pub use context_enrichment_agent::{
    AgentExecutionLog, AgentStep, ContextEnrichmentAgent, ContextEnrichmentResult, EnrichmentMode,
    PlannedSearch,
};
pub use factory::AgenticNarrativeFactory;
pub use narrative_tools::{
    AnalyzeLorebookTool, AnalyzeTextSignificanceTool, CreateBatchLorebookEntriesTool,
    CreateChronicleEventTool, CreateLorebookEntryTool, SearchKnowledgeBaseTool,
    UpdateLorebookEntryTool,
};
pub use persona_context::{CharacterContext, UserPersonaContext};
pub use registry::ToolRegistry;
pub use state_manager_agent::{StateManagerAgent, StateManagerConfig};
pub use tools::{ScribeTool, ToolError, ToolParams, ToolResult};
