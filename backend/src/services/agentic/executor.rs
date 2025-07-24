//! Defines the `ToolExecutor` for running agentic tools.

use std::sync::Arc;

use super::{
    registry::ToolRegistry,
    tools::{ToolError, ToolParams, ToolResult},
};
use crate::auth::session_dek::SessionDek;

/// The `ToolExecutor` is responsible for executing a tool from a `ToolRegistry`.
pub struct ToolExecutor {
    registry: Arc<ToolRegistry>,
}

impl ToolExecutor {
    /// Creates a new `ToolExecutor` with the given tool registry.
    pub fn new(registry: Arc<ToolRegistry>) -> Self {
        Self { registry }
    }

    /// Executes a tool by name with the given parameters.
    ///
    /// It looks up the tool in the registry and calls its `execute` method.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the tool to execute.
    /// * `params` - The JSON parameters to pass to the tool.
    ///
    /// # Returns
    ///
    /// * `Ok(ToolResult)` if the tool executes successfully.
    /// * `Err(ToolError)` if the tool is not found or if execution fails.
    pub async fn execute_tool(
        &self,
        name: &str,
        params: &ToolParams,
        session_dek: &SessionDek,
    ) -> Result<ToolResult, ToolError> {
        let tool = self.registry.get_tool(name)?;
        tool.execute(params, session_dek).await
    }
}