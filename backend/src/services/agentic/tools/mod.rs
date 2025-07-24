//! Defines the core traits and data structures for the agentic tool framework.

pub mod hierarchy_tools;
pub mod ai_powered_tools;
pub mod ai_entity_resolution;
pub mod ai_narrative_analysis;
pub mod structured_output;
pub mod lorebook_tools;
pub mod chronicle_tools;
pub mod inventory_tools;
pub mod example_self_registering;

// AI-driven focused tool modules (replaced world_interaction_tools)
pub mod entity_crud_tools;
pub mod spatial_interaction_tools;
pub mod relationship_interaction_tools;
pub mod general_interaction_tools;
pub mod narrative_tool_wrappers;

use async_trait::async_trait;
use serde_json::Value;
use std::error::Error;
use std::fmt;

use crate::{errors::AppError, auth::session_dek::SessionDek};

/// A simple wrapper for tool parameters, which are expected to be a JSON object.
pub type ToolParams = Value;

/// A simple wrapper for the result of a tool execution.
pub type ToolResult = Value;

/// Represents a tool that can be executed by an AI agent.
///
/// This trait defines a standardized interface for all tools within the Scribe system.
/// The `description` and `input_schema` are crucial for the AI's ability to
/// understand and correctly use the tool.
#[async_trait]
pub trait ScribeTool: Send + Sync {
    /// Returns the unique name of the tool.
    fn name(&self) -> &'static str;

    /// Returns a detailed description of what the tool does.
    /// This is used by the LLM to decide when to use the tool.
    fn description(&self) -> &'static str;

    /// Returns a JSON schema describing the expected input parameters for the tool.
    /// This helps the LLM to format its requests correctly.
    fn input_schema(&self) -> Value;

    /// Executes the tool with the given parameters and session DEK for encryption/decryption.
    /// 
    /// The SessionDek is required for all tools to handle encrypted data according to the
    /// encryption architecture. Tools must decrypt any sensitive data before AI processing
    /// and re-encrypt results before storage.
    async fn execute(&self, params: &ToolParams, session_dek: &SessionDek) -> Result<ToolResult, ToolError>;
}

/// An error that can occur during tool execution.
#[derive(Debug)]
pub enum ToolError {
    /// The provided parameters do not match the tool's input schema.
    InvalidParams(String),
    /// An error occurred during the tool's execution.
    ExecutionFailed(String),
    /// An underlying application error occurred.
    AppError(AppError),
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToolError::InvalidParams(msg) => write!(f, "Invalid parameters: {}", msg),
            ToolError::ExecutionFailed(msg) => write!(f, "Tool execution failed: {}", msg),
            ToolError::AppError(err) => write!(f, "Application error: {}", err),
        }
    }
}

impl Error for ToolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ToolError::AppError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<AppError> for ToolError {
    fn from(err: AppError) -> Self {
        ToolError::AppError(err)
    }
}

impl From<serde_json::Error> for ToolError {
    fn from(err: serde_json::Error) -> Self {
        ToolError::InvalidParams(format!("JSON serialization error: {}", err))
    }
}