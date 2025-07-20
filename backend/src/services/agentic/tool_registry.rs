//! Dynamic Tool Registry System
//! 
//! This module provides a self-registering system for AI agent tools.
//! Each tool can register itself with comprehensive metadata for AI understanding.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};
use serde_json::Value as JsonValue;
use tracing::info;
use once_cell::sync::Lazy;

use crate::errors::AppError;
use super::tools::{ScribeTool, ToolError};

// Global tool registry instance
static TOOL_REGISTRY: Lazy<Mutex<ToolRegistry>> = Lazy::new(|| {
    Mutex::new(ToolRegistry::new())
});

/// Extended metadata for tools beyond the basic ScribeTool trait
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMetadata {
    /// The tool name (same as ScribeTool::name())
    pub name: String,
    /// Human-readable description (same as ScribeTool::description())
    pub description: String,
    /// Tool category for organization
    pub category: ToolCategory,
    /// Usage examples to help AI understand the tool
    pub usage_examples: Vec<UsageExample>,
    /// When this tool should be used
    pub when_to_use: String,
    /// When this tool should NOT be used
    pub when_not_to_use: Option<String>,
    /// Dependencies on other tools
    pub depends_on: Vec<String>,
    /// Typical execution time
    pub execution_time: ExecutionTime,
    /// Whether this tool makes external calls
    pub external_calls: bool,
    /// Whether this tool modifies state
    pub modifies_state: bool,
    /// Tags for additional categorization
    pub tags: Vec<String>,
    /// Schema from ScribeTool::input_schema()
    pub input_schema: JsonValue,
    /// Expected output format
    pub output_format: String,
    /// Access control policy for this tool
    pub access_policy: Option<ToolAccessPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ToolCategory {
    /// Tools for knowledge extraction and analysis
    Extraction,
    /// Tools that create or modify data
    Creation,
    /// Tools for searching and querying
    Search,
    /// Tools for entity management
    EntityManagement,
    /// Tools for hierarchy operations
    Hierarchy,
    /// Tools for AI-powered analysis
    AIAnalysis,
    /// Tools for world state queries
    WorldState,
    /// Tools for narrative operations
    Narrative,
    /// General utility tools
    Utility,
}

/// Agent type for role-based tool access control
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentType {
    /// Strategic Agent - High-level narrative planning
    Strategic,
    /// Tactical Agent - Mid-level coordination and planning
    Tactical,
    /// Perception Agent - Low-level world state observation and updates
    Perception,
    /// Orchestrator - Overall system coordination
    Orchestrator,
}

/// Tool access policy defining which agents can use which tools
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolAccessPolicy {
    /// Which agent types can use this tool
    pub allowed_agents: Vec<AgentType>,
    /// Priority level for this tool (higher = more important)
    pub priority: u8,
    /// Whether this tool is required for the agent's core functionality
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageExample {
    pub scenario: String,
    pub input: JsonValue,
    pub expected_outcome: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ExecutionTime {
    /// < 100ms
    Instant,
    /// < 1s
    Fast,
    /// 1-5s
    Moderate,
    /// > 5s
    Slow,
}

/// Enhanced tool registry with metadata support
pub struct ToolRegistry {
    /// Map of tool name to tool instance
    tools: HashMap<String, Arc<dyn ScribeTool>>,
    /// Map of tool name to extended metadata
    metadata: HashMap<String, ToolMetadata>,
}

impl ToolRegistry {
    fn new() -> Self {
        Self {
            tools: HashMap::new(),
            metadata: HashMap::new(),
        }
    }
    
    /// Register a tool with its metadata
    pub fn register_tool(
        tool: Arc<dyn ScribeTool>,
        metadata: ToolMetadata,
    ) -> Result<(), AppError> {
        let mut registry = TOOL_REGISTRY.lock().map_err(|_| {
            AppError::InternalServerErrorGeneric("Failed to acquire registry lock".to_string())
        })?;
        
        let name = tool.name().to_string();
        
        // Validate metadata matches tool
        if metadata.name != name {
            return Err(AppError::InvalidInput(
                format!("Tool name '{}' doesn't match metadata name '{}'", name, metadata.name)
            ));
        }
        
        // Check for duplicates - just skip if already registered
        if registry.tools.contains_key(&name) {
            info!("Tool '{}' already registered, skipping", name);
            return Ok(());
        }
        
        info!("Registering tool: {} (category: {:?})", name, metadata.category);
        
        registry.tools.insert(name.clone(), tool);
        registry.metadata.insert(name, metadata);
        
        Ok(())
    }
    
    /// Get a tool by name
    pub fn get_tool(name: &str) -> Result<Arc<dyn ScribeTool>, ToolError> {
        let registry = TOOL_REGISTRY.lock().map_err(|_| {
            ToolError::ExecutionFailed("Failed to acquire registry lock".to_string())
        })?;
        
        registry.tools
            .get(name)
            .cloned()
            .ok_or_else(|| ToolError::ExecutionFailed(format!("Tool '{}' not found", name)))
    }
    
    /// Get metadata for a tool
    pub fn get_metadata(name: &str) -> Option<ToolMetadata> {
        let registry = TOOL_REGISTRY.lock().ok()?;
        registry.metadata.get(name).cloned()
    }
    
    /// Update metadata for a specific tool
    pub fn update_metadata(name: &str, metadata: ToolMetadata) -> Result<(), ToolError> {
        let mut registry = TOOL_REGISTRY.lock().map_err(|_| {
            ToolError::ExecutionFailed("Failed to acquire registry lock".to_string())
        })?;
        
        if registry.tools.contains_key(name) {
            registry.metadata.insert(name.to_string(), metadata);
            Ok(())
        } else {
            Err(ToolError::ExecutionFailed(format!("Tool '{}' not found", name)))
        }
    }
    
    /// List all registered tool names
    pub fn list_tool_names() -> Vec<String> {
        let registry = TOOL_REGISTRY.lock().unwrap();
        registry.tools.keys().cloned().collect()
    }
    
    /// Get all tools in a category
    pub fn get_tools_by_category(category: ToolCategory) -> Vec<String> {
        let registry = TOOL_REGISTRY.lock().unwrap();
        registry.metadata
            .iter()
            .filter(|(_, meta)| meta.category == category)
            .map(|(name, _)| name.clone())
            .collect()
    }
    
    /// Get tools with specific tags
    pub fn get_tools_by_tag(tag: &str) -> Vec<String> {
        let registry = TOOL_REGISTRY.lock().unwrap();
        registry.metadata
            .iter()
            .filter(|(_, meta)| meta.tags.contains(&tag.to_string()))
            .map(|(name, _)| name.clone())
            .collect()
    }
    
    /// Generate comprehensive documentation for all tools
    pub fn generate_tool_documentation() -> String {
        let registry = TOOL_REGISTRY.lock().unwrap();
        let mut doc = String::from("# AVAILABLE TOOLS - Dynamic Registry\n\n");
        
        // Group by category
        let mut by_category: HashMap<ToolCategory, Vec<(&String, &ToolMetadata)>> = HashMap::new();
        
        for (name, meta) in &registry.metadata {
            by_category.entry(meta.category.clone())
                .or_insert_with(Vec::new)
                .push((name, meta));
        }
        
        // Sort categories for consistent output
        let mut categories: Vec<_> = by_category.keys().cloned().collect();
        categories.sort_by_key(|c| format!("{:?}", c));
        
        for category in categories {
            doc.push_str(&format!("\n## {:?} Tools\n\n", category));
            
            if let Some(tools) = by_category.get(&category) {
                for (name, meta) in tools {
                    doc.push_str(&format!("### {}\n", name));
                    doc.push_str(&format!("**Description:** {}\n\n", meta.description));
                    doc.push_str(&format!("**When to use:** {}\n\n", meta.when_to_use));
                    
                    if let Some(when_not) = &meta.when_not_to_use {
                        doc.push_str(&format!("**When NOT to use:** {}\n\n", when_not));
                    }
                    
                    doc.push_str("**Input Schema:**\n```json\n");
                    doc.push_str(&serde_json::to_string_pretty(&meta.input_schema).unwrap());
                    doc.push_str("\n```\n\n");
                    
                    doc.push_str(&format!("**Output Format:** {}\n\n", meta.output_format));
                    
                    if !meta.usage_examples.is_empty() {
                        doc.push_str("**Usage Examples:**\n");
                        for (i, example) in meta.usage_examples.iter().enumerate() {
                            doc.push_str(&format!("\n{}. **Scenario:** {}\n", i + 1, example.scenario));
                            doc.push_str("   **Input:**\n   ```json\n");
                            doc.push_str(&format!("   {}\n", serde_json::to_string_pretty(&example.input).unwrap()));
                            doc.push_str("   ```\n");
                            doc.push_str(&format!("   **Expected Outcome:** {}\n", example.expected_outcome));
                        }
                    }
                    
                    doc.push_str(&format!("\n**Execution Time:** {:?}\n", meta.execution_time));
                    doc.push_str(&format!("**Modifies State:** {}\n", meta.modifies_state));
                    doc.push_str(&format!("**External Calls:** {}\n", meta.external_calls));
                    
                    if !meta.depends_on.is_empty() {
                        doc.push_str(&format!("**Dependencies:** {}\n", meta.depends_on.join(", ")));
                    }
                    
                    if !meta.tags.is_empty() {
                        doc.push_str(&format!("**Tags:** {}\n", meta.tags.join(", ")));
                    }
                    
                    doc.push_str("\n---\n");
                }
            }
        }
        
        doc
    }
    
    /// Generate a concise tool reference for AI agents
    pub fn generate_tool_reference() -> String {
        let registry = TOOL_REGISTRY.lock().unwrap();
        let mut reference = String::from("TOOL REFERENCE:\n\n");
        
        for (name, meta) in &registry.metadata {
            reference.push_str(&format!(
                "- **{}** ({:?}): {} Use when: {}\n",
                name,
                meta.category,
                meta.description,
                meta.when_to_use
            ));
        }
        
        reference
    }
    
    /// Get tools suitable for a specific context
    pub fn get_contextual_tools(context: &ToolContext) -> Vec<String> {
        let registry = TOOL_REGISTRY.lock().unwrap();
        let mut suitable_tools = Vec::new();
        
        for (name, meta) in &registry.metadata {
            // Filter based on context requirements
            if context.needs_fast_execution && meta.execution_time == ExecutionTime::Slow {
                continue;
            }
            
            if context.read_only && meta.modifies_state {
                continue;
            }
            
            if !context.allow_external_calls && meta.external_calls {
                continue;
            }
            
            if let Some(required_category) = &context.required_category {
                if &meta.category != required_category {
                    continue;
                }
            }
            
            if let Some(required_tags) = &context.required_tags {
                if !required_tags.iter().all(|tag| meta.tags.contains(tag)) {
                    continue;
                }
            }
            
            suitable_tools.push(name.clone());
        }
        
        suitable_tools
    }
    
    /// Get tools available to a specific agent type
    pub fn get_tools_for_agent(agent_type: AgentType) -> Vec<String> {
        let registry = TOOL_REGISTRY.lock().unwrap();
        registry.metadata
            .iter()
            .filter(|(_, meta)| {
                // If no access policy is defined, tool is available to all agents
                if let Some(policy) = &meta.access_policy {
                    policy.allowed_agents.contains(&agent_type)
                } else {
                    true
                }
            })
            .map(|(name, _)| name.clone())
            .collect()
    }
    
    /// Get high-priority tools for a specific agent
    pub fn get_priority_tools_for_agent(agent_type: AgentType, min_priority: u8) -> Vec<String> {
        let registry = TOOL_REGISTRY.lock().unwrap();
        registry.metadata
            .iter()
            .filter(|(_, meta)| {
                if let Some(policy) = &meta.access_policy {
                    policy.allowed_agents.contains(&agent_type) && policy.priority >= min_priority
                } else {
                    false
                }
            })
            .map(|(name, _)| name.clone())
            .collect()
    }
    
    /// Get required tools for a specific agent
    pub fn get_required_tools_for_agent(agent_type: AgentType) -> Vec<String> {
        let registry = TOOL_REGISTRY.lock().unwrap();
        registry.metadata
            .iter()
            .filter(|(_, meta)| {
                if let Some(policy) = &meta.access_policy {
                    policy.allowed_agents.contains(&agent_type) && policy.required
                } else {
                    false
                }
            })
            .map(|(name, _)| name.clone())
            .collect()
    }
    
    /// Check if an agent has access to a specific tool
    pub fn agent_can_access_tool(agent_type: AgentType, tool_name: &str) -> bool {
        let registry = TOOL_REGISTRY.lock().unwrap();
        if let Some(meta) = registry.metadata.get(tool_name) {
            if let Some(policy) = &meta.access_policy {
                policy.allowed_agents.contains(&agent_type)
            } else {
                // No policy means accessible to all
                true
            }
        } else {
            false
        }
    }
    
    /// Generate a tool reference specific to an agent type with detailed usage information
    pub fn generate_agent_tool_reference(agent_type: AgentType) -> String {
        let registry = TOOL_REGISTRY.lock().unwrap();
        let mut reference = format!("# AVAILABLE TOOLS FOR {} AGENT\n\n", 
            format!("{:?}", agent_type).to_uppercase());
        
        // Add agent-specific guidance
        let guidance = crate::services::agentic::tool_access_config::get_agent_tool_recommendations(agent_type);
        reference.push_str(guidance);
        reference.push_str("\n\n## YOUR AVAILABLE TOOLS:\n\n");
        
        // Collect tools with their policies
        let mut tools_with_priority: Vec<(String, &ToolMetadata, u8, bool)> = Vec::new();
        
        for (name, meta) in &registry.metadata {
            if let Some(policy) = &meta.access_policy {
                if policy.allowed_agents.contains(&agent_type) {
                    tools_with_priority.push((name.clone(), meta, policy.priority, policy.required));
                }
            } else {
                // Tools without policies are available to all agents
                tools_with_priority.push((name.clone(), meta, 5, false));
            }
        }
        
        // Sort by priority (descending) then by name
        tools_with_priority.sort_by(|a, b| {
            b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0))
        });
        
        // Group by priority level for better organization
        let high_priority: Vec<_> = tools_with_priority.iter()
            .filter(|(_, _, priority, _)| *priority >= 8)
            .collect();
        let medium_priority: Vec<_> = tools_with_priority.iter()
            .filter(|(_, _, priority, _)| *priority >= 5 && *priority < 8)
            .collect();
        let low_priority: Vec<_> = tools_with_priority.iter()
            .filter(|(_, _, priority, _)| *priority < 5)
            .collect();
        
        // Format high priority tools
        if !high_priority.is_empty() {
            reference.push_str("### 🔴 HIGH PRIORITY TOOLS\n\n");
            for (name, meta, priority, required) in &high_priority {
                Self::format_tool_entry(&mut reference, name, meta, *priority, *required);
            }
        }
        
        // Format medium priority tools
        if !medium_priority.is_empty() {
            reference.push_str("### 🟡 MEDIUM PRIORITY TOOLS\n\n");
            for (name, meta, priority, required) in &medium_priority {
                Self::format_tool_entry(&mut reference, name, meta, *priority, *required);
            }
        }
        
        // Format low priority tools
        if !low_priority.is_empty() {
            reference.push_str("### 🟢 LOW PRIORITY TOOLS\n\n");
            for (name, meta, priority, required) in &low_priority {
                Self::format_tool_entry(&mut reference, name, meta, *priority, *required);
            }
        }
        
        // Add summary
        let total = tools_with_priority.len();
        let required_count = tools_with_priority.iter().filter(|(_, _, _, req)| *req).count();
        
        reference.push_str(&format!("\n## TOOL SUMMARY\n"));
        reference.push_str(&format!("- Total Available Tools: {}\n", total));
        reference.push_str(&format!("- Required Tools: {}\n", required_count));
        reference.push_str(&format!("- High Priority: {}\n", high_priority.len()));
        reference.push_str(&format!("- Medium Priority: {}\n", medium_priority.len()));
        reference.push_str(&format!("- Low Priority: {}\n", low_priority.len()));
        
        reference
    }
    
    /// Format a single tool entry with usage information
    fn format_tool_entry(doc: &mut String, name: &str, meta: &ToolMetadata, priority: u8, required: bool) {
        let req_marker = if required { " [REQUIRED]" } else { "" };
        
        doc.push_str(&format!("#### `{}`{}\n\n", name, req_marker));
        doc.push_str(&format!("**Description:** {}\n\n", meta.description));
        doc.push_str(&format!("**When to use:** {}\n\n", meta.when_to_use));
        
        if let Some(when_not) = &meta.when_not_to_use {
            doc.push_str(&format!("**When NOT to use:** {}\n\n", when_not));
        }
        
        // Add usage examples if available
        if !meta.usage_examples.is_empty() {
            doc.push_str("**Examples:**\n");
            for example in &meta.usage_examples {
                doc.push_str(&format!("- *{}*: {}\n", example.scenario, example.expected_outcome));
            }
            doc.push_str("\n");
        }
        
        // Add simple input schema info
        doc.push_str(&format!("**Input Format:** `{}`\n", name));
        if let Ok(schema_str) = serde_json::to_string(&meta.input_schema) {
            if schema_str.len() < 200 {  // Only show small schemas inline
                doc.push_str(&format!("```json\n{}\n```\n", 
                    serde_json::to_string_pretty(&meta.input_schema).unwrap_or_default()));
            } else {
                doc.push_str(" (see tool documentation for full schema)\n");
            }
        }
        
        doc.push_str(&format!("**Output:** {}\n", meta.output_format));
        
        // Performance characteristics
        let perf = match meta.execution_time {
            ExecutionTime::Instant => "Instant (< 100ms)",
            ExecutionTime::Fast => "Fast (< 1s)",
            ExecutionTime::Moderate => "Moderate (1-5s)",
            ExecutionTime::Slow => "Slow (> 5s)",
        };
        doc.push_str(&format!("**Performance:** {} | ", perf));
        doc.push_str(&format!("External Calls: {} | ", if meta.external_calls { "Yes" } else { "No" }));
        doc.push_str(&format!("Modifies State: {}\n", if meta.modifies_state { "Yes" } else { "No" }));
        
        doc.push_str("\n---\n\n");
    }
}

/// Context for filtering tools
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub needs_fast_execution: bool,
    pub read_only: bool,
    pub allow_external_calls: bool,
    pub required_category: Option<ToolCategory>,
    pub required_tags: Option<Vec<String>>,
}

impl Default for ToolContext {
    fn default() -> Self {
        Self {
            needs_fast_execution: false,
            read_only: false,
            allow_external_calls: true,
            required_category: None,
            required_tags: None,
        }
    }
}

/// Macro to simplify tool registration
#[macro_export]
macro_rules! register_tool {
    ($tool:expr, $metadata:expr) => {
        {
            ToolRegistry::register_tool(Arc::new($tool), $metadata)
                .expect(&format!("Failed to register tool: {}", $metadata.name));
        }
    };
}

/// Builder for creating ToolMetadata
pub struct ToolMetadataBuilder {
    name: String,
    description: String,
    category: ToolCategory,
    usage_examples: Vec<UsageExample>,
    when_to_use: String,
    when_not_to_use: Option<String>,
    depends_on: Vec<String>,
    execution_time: ExecutionTime,
    external_calls: bool,
    modifies_state: bool,
    tags: Vec<String>,
    input_schema: JsonValue,
    output_format: String,
    access_policy: Option<ToolAccessPolicy>,
}

impl ToolMetadataBuilder {
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            category: ToolCategory::Utility,
            usage_examples: Vec::new(),
            when_to_use: String::new(),
            when_not_to_use: None,
            depends_on: Vec::new(),
            execution_time: ExecutionTime::Fast,
            external_calls: false,
            modifies_state: false,
            tags: Vec::new(),
            input_schema: JsonValue::Null,
            output_format: "JSON object".to_string(),
            access_policy: None,
        }
    }
    
    pub fn category(mut self, category: ToolCategory) -> Self {
        self.category = category;
        self
    }
    
    pub fn when_to_use(mut self, when: impl Into<String>) -> Self {
        self.when_to_use = when.into();
        self
    }
    
    pub fn when_not_to_use(mut self, when: impl Into<String>) -> Self {
        self.when_not_to_use = Some(when.into());
        self
    }
    
    pub fn example(mut self, scenario: impl Into<String>, input: JsonValue, outcome: impl Into<String>) -> Self {
        self.usage_examples.push(UsageExample {
            scenario: scenario.into(),
            input,
            expected_outcome: outcome.into(),
        });
        self
    }
    
    pub fn depends_on(mut self, tools: Vec<String>) -> Self {
        self.depends_on = tools;
        self
    }
    
    pub fn execution_time(mut self, time: ExecutionTime) -> Self {
        self.execution_time = time;
        self
    }
    
    pub fn external_calls(mut self, has_external: bool) -> Self {
        self.external_calls = has_external;
        self
    }
    
    pub fn modifies_state(mut self, modifies: bool) -> Self {
        self.modifies_state = modifies;
        self
    }
    
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
    
    pub fn input_schema(mut self, schema: JsonValue) -> Self {
        self.input_schema = schema;
        self
    }
    
    pub fn output_format(mut self, format: impl Into<String>) -> Self {
        self.output_format = format.into();
        self
    }
    
    pub fn access_policy(mut self, policy: ToolAccessPolicy) -> Self {
        self.access_policy = Some(policy);
        self
    }
    
    pub fn allowed_agents(mut self, agents: Vec<AgentType>) -> Self {
        let policy = self.access_policy.get_or_insert(ToolAccessPolicy {
            allowed_agents: Vec::new(),
            priority: 5,
            required: false,
        });
        policy.allowed_agents = agents;
        self
    }
    
    pub fn priority(mut self, priority: u8) -> Self {
        let policy = self.access_policy.get_or_insert(ToolAccessPolicy {
            allowed_agents: Vec::new(),
            priority: 5,
            required: false,
        });
        policy.priority = priority;
        self
    }
    
    pub fn required(mut self, required: bool) -> Self {
        let policy = self.access_policy.get_or_insert(ToolAccessPolicy {
            allowed_agents: Vec::new(),
            priority: 5,
            required: false,
        });
        policy.required = required;
        self
    }
    
    pub fn build(self) -> ToolMetadata {
        ToolMetadata {
            name: self.name,
            description: self.description,
            category: self.category,
            usage_examples: self.usage_examples,
            when_to_use: self.when_to_use,
            when_not_to_use: self.when_not_to_use,
            depends_on: self.depends_on,
            execution_time: self.execution_time,
            external_calls: self.external_calls,
            modifies_state: self.modifies_state,
            tags: self.tags,
            input_schema: self.input_schema,
            output_format: self.output_format,
            access_policy: self.access_policy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_tool_registration() {
        // Create a mock tool
        struct MockTool;
        
        #[async_trait::async_trait]
        impl ScribeTool for MockTool {
            fn name(&self) -> &'static str {
                "mock_tool"
            }
            
            fn description(&self) -> &'static str {
                "A mock tool for testing"
            }
            
            fn input_schema(&self) -> JsonValue {
                json!({
                    "type": "object",
                    "properties": {
                        "test": {"type": "string"}
                    }
                })
            }
            
            async fn execute(&self, _params: &super::super::tools::ToolParams) -> Result<super::super::tools::ToolResult, ToolError> {
                Ok(json!({"result": "success"}))
            }
        }
        
        // Create metadata
        let metadata = ToolMetadataBuilder::new("mock_tool", "A mock tool for testing")
            .category(ToolCategory::Utility)
            .when_to_use("When testing the registry")
            .execution_time(ExecutionTime::Instant)
            .build();
        
        // Register the tool
        ToolRegistry::register_tool(Arc::new(MockTool), metadata).unwrap();
        
        // Verify registration
        assert!(ToolRegistry::list_tool_names().contains(&"mock_tool".to_string()));
        assert!(ToolRegistry::get_tool("mock_tool").is_ok());
        assert!(ToolRegistry::get_metadata("mock_tool").is_some());
    }
}