//! Defines the `ToolRegistry` for managing and accessing agentic tools.

use std::collections::HashMap;
use std::sync::Arc;

use super::tools::{ScribeTool, ToolError};

/// A registry for storing and accessing all available `ScribeTool` implementations.
///
/// The registry holds a collection of tools, each wrapped in an `Arc` to allow
/// for shared, thread-safe access.
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn ScribeTool>>,
}

impl ToolRegistry {
    /// Creates a new, empty `ToolRegistry`.
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Adds a tool to the registry.
    ///
    /// The tool is stored by its name, as defined by the `ScribeTool::name` method.
    pub fn add_tool(&mut self, tool: Arc<dyn ScribeTool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    /// Retrieves a tool from the registry by its name.
    ///
    /// # Returns
    ///
    /// * `Ok(Arc<dyn ScribeTool>)` if the tool is found.
    /// * `Err(ToolError::ExecutionFailed)` if no tool with the given name is registered.
    pub fn get_tool(&self, name: &str) -> Result<Arc<dyn ScribeTool>, ToolError> {
        self.tools
            .get(name)
            .cloned()
            .ok_or_else(|| ToolError::ExecutionFailed(format!("Tool '{}' not found", name)))
    }

    /// Returns a list of all tool names in the registry.
    pub fn list_tools(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}