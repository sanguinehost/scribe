use crate::IntelligenceError;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

#[async_trait]
pub trait McpTool: Send + Sync {
    fn definition(&self) -> McpToolDefinition;
    async fn call(&self, arguments: Value) -> Result<Value, IntelligenceError>;
}

pub struct McpRegistry {
    tools: Vec<Box<dyn McpTool>>,
}

impl McpRegistry {
    pub fn new() -> Self {
        Self { tools: Vec::new() }
    }

    pub fn register(&mut self, tool: Box<dyn McpTool>) {
        self.tools.push(tool);
    }

    pub fn list_tools(&self) -> Vec<McpToolDefinition> {
        self.tools.iter().map(|t| t.definition()).collect()
    }

    pub async fn call_tool(&self, name: &str, arguments: Value) -> Result<Value, IntelligenceError> {
        for tool in &self.tools {
            if tool.definition().name == name {
                return tool.call(arguments).await;
            }
        }
        Err(IntelligenceError::ToolError(format!("Tool not found: {}", name)))
    }
}
