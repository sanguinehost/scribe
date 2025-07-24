// backend/src/services/orchestrator/mod.rs
//
// Orchestrator Agent Module
// Epic 8: Orchestrator-Driven Intelligent Agent System
//
// This module implements the Orchestrator Agent that processes enrichment tasks
// from the durable queue using a 5-phase reasoning loop with Progressive Response optimization.

pub mod agent;
pub mod types;
pub mod reasoning;
pub mod errors;
pub mod structured_output;

pub use agent::{OrchestratorAgent, OrchestratorConfig};
pub use types::*;
pub use reasoning::*;
pub use errors::OrchestratorError;
pub use structured_output::*;