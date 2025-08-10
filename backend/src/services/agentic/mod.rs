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
pub mod narrative_tools;
pub mod factory;
pub mod registry;
pub mod tools;
pub mod persona_context;

#[cfg(test)]
mod narrative_tools_tests;

// Re-export key types for convenience
pub use agent_runner::{NarrativeAgentRunner, NarrativeWorkflowConfig, NarrativeWorkflowResult};
pub use context_enrichment_agent::{
    ContextEnrichmentAgent, ContextEnrichmentResult, EnrichmentMode,
    AgentExecutionLog, AgentStep, PlannedSearch,
};
pub use factory::AgenticNarrativeFactory;
pub use registry::ToolRegistry;
pub use tools::{ScribeTool, ToolError, ToolParams, ToolResult};
pub use persona_context::UserPersonaContext;
pub use narrative_tools::{
    CreateChronicleEventTool, CreateLorebookEntryTool, 
    AnalyzeTextSignificanceTool, ExtractTemporalEventsTool, ExtractWorldConceptsTool,
    SearchKnowledgeBaseTool, UpdateLorebookEntryTool
};