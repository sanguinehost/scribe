//! Unified Tool Registry with AI-Powered Discovery and Security
//! 
//! This module provides a secure, self-registering tool system with AI-powered
//! discovery capabilities for the orchestrator-driven progressive action system.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use once_cell::sync::Lazy;
use serde::{Serialize, Deserialize};
use serde_json::Value as JsonValue;
use async_trait::async_trait;
use tracing::info;
use uuid::Uuid;

use crate::{
    errors::AppError,
    services::agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    auth::session_dek::SessionDek,
};

/// Global unified tool registry instance
static UNIFIED_REGISTRY: Lazy<Arc<RwLock<UnifiedToolRegistry>>> = Lazy::new(|| {
    Arc::new(RwLock::new(UnifiedToolRegistry::new()))
});

/// Enhanced trait for self-registering tools with embedded metadata
#[async_trait]
pub trait SelfRegisteringTool: ScribeTool + Send + Sync {
    /// Build complete metadata for this tool
    fn metadata(&self) -> ToolMetadata {
        ToolMetadata {
            name: self.name().to_string(),
            description: self.description().to_string(),
            category: self.category(),
            capabilities: self.capabilities(),
            when_to_use: self.when_to_use(),
            when_not_to_use: self.when_not_to_use(),
            usage_examples: self.usage_examples(),
            security_policy: self.security_policy(),
            resource_requirements: self.resource_requirements(),
            dependencies: self.dependencies(),
            tags: self.tags(),
            input_schema: self.input_schema(),
            output_schema: self.output_schema(),
            error_codes: self.error_codes(),
            version: self.version().to_string(),
        }
    }
    
    /// Tool category for organization and discovery
    fn category(&self) -> ToolCategory;
    
    /// What this tool can do (for AI understanding)
    fn capabilities(&self) -> Vec<ToolCapability>;
    
    /// When agents should use this tool
    fn when_to_use(&self) -> String;
    
    /// When agents should NOT use this tool
    fn when_not_to_use(&self) -> String;
    
    /// Usage examples for AI learning
    fn usage_examples(&self) -> Vec<ToolExample>;
    
    /// Security policy for this tool
    fn security_policy(&self) -> ToolSecurityPolicy;
    
    /// Resource requirements (for capacity planning)
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements::default()
    }
    
    /// Dependencies on other tools
    fn dependencies(&self) -> Vec<String> {
        Vec::new()
    }
    
    /// Tags for enhanced discovery
    fn tags(&self) -> Vec<String> {
        Vec::new()
    }
    
    /// Output schema (in addition to input schema from ScribeTool)
    fn output_schema(&self) -> JsonValue;
    
    /// Possible error codes this tool can return
    fn error_codes(&self) -> Vec<ErrorCode> {
        Vec::new()
    }
    
    /// Tool version for compatibility tracking
    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

/// Complete tool metadata for AI understanding and discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMetadata {
    pub name: String,
    pub description: String,
    pub category: ToolCategory,
    pub capabilities: Vec<ToolCapability>,
    pub when_to_use: String,
    pub when_not_to_use: String,
    pub usage_examples: Vec<ToolExample>,
    pub security_policy: ToolSecurityPolicy,
    pub resource_requirements: ResourceRequirements,
    pub dependencies: Vec<String>,
    pub tags: Vec<String>,
    pub input_schema: JsonValue,
    pub output_schema: JsonValue,
    pub error_codes: Vec<ErrorCode>,
    pub version: String,
}

/// Tool categories aligned with orchestrator reasoning phases
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolCategory {
    /// Tools for perceiving and understanding the world state
    Perception,
    /// Tools for analyzing and extracting information
    Analysis,
    /// Tools for strategic planning and decision making
    Strategic,
    /// Tools for tactical execution planning
    Tactical,
    /// Tools for creating or modifying entities/data
    Creation,
    /// Tools for searching and querying
    Discovery,
    /// Tools for managing entities and relationships
    Management,
    /// Tools for generating content with AI
    Generation,
    /// Tools for validation and verification
    Validation,
}

/// What a tool can do (capability-based discovery)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCapability {
    /// Action verb (e.g., "analyze", "create", "query")
    pub action: String,
    /// Target of the action (e.g., "narrative text", "entities", "lorebook entries")
    pub target: String,
    /// Optional context (e.g., "for significance", "by location")
    pub context: Option<String>,
}

/// Example usage for AI learning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExample {
    pub scenario: String,
    pub input: JsonValue,
    pub expected_output: String,
}

/// Security policy with granular controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSecurityPolicy {
    /// Which agents can use this tool
    pub allowed_agents: Vec<AgentType>,
    /// Required capabilities for access
    pub required_capabilities: Vec<String>,
    /// Rate limiting
    pub rate_limit: Option<RateLimit>,
    /// Data access restrictions
    pub data_access: DataAccessPolicy,
    /// Audit requirements
    pub audit_level: AuditLevel,
}

/// Agent types in the hierarchical system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentType {
    /// Orchestrator - coordinates all agents
    Orchestrator,
    /// Strategic Agent - high-level planning
    Strategic,
    /// Tactical Agent - execution planning
    Tactical,
    /// Perception Agent - world state observation
    Perception,
    /// Custom agent type for extensibility
    Custom(u32),
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Max calls per minute
    pub calls_per_minute: u32,
    /// Max calls per hour
    pub calls_per_hour: u32,
    /// Burst allowance
    pub burst_size: u32,
}

/// Data access restrictions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAccessPolicy {
    /// Can access user's private data
    pub user_data: bool,
    /// Can access system data
    pub system_data: bool,
    /// Can modify data
    pub write_access: bool,
    /// Specific data scopes allowed
    pub allowed_scopes: Vec<String>,
}

/// Audit level for tool usage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditLevel {
    /// No audit logging
    None,
    /// Log basic usage
    Basic,
    /// Log with parameters
    Detailed,
    /// Log everything including results
    Full,
}

/// Resource requirements for capacity planning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    /// Estimated memory usage in MB
    pub memory_mb: u32,
    /// Estimated execution time
    pub execution_time: ExecutionTime,
    /// Whether this makes external API calls
    pub external_calls: bool,
    /// Whether this performs heavy computation
    pub compute_intensive: bool,
}

impl Default for ResourceRequirements {
    fn default() -> Self {
        Self {
            memory_mb: 10,
            execution_time: ExecutionTime::Fast,
            external_calls: false,
            compute_intensive: false,
        }
    }
}

/// Execution time categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionTime {
    /// < 100ms
    Fast,
    /// 100ms - 1s
    Moderate,
    /// 1s - 5s
    Slow,
    /// > 5s
    VerySlow,
}

/// Error codes for better error handling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorCode {
    pub code: String,
    pub description: String,
    pub retry_able: bool,
}

/// The unified tool registry
pub struct UnifiedToolRegistry {
    /// All registered tools by name
    tools: HashMap<String, RegisteredTool>,
    /// Tools organized by category
    by_category: HashMap<ToolCategory, Vec<String>>,
    /// Tools organized by capability
    by_capability: HashMap<String, Vec<String>>,
    /// AI context cache for faster discovery
    discovery_context: Option<DiscoveryContext>,
}

/// A registered tool with its metadata and implementation
struct RegisteredTool {
    implementation: Arc<dyn SelfRegisteringTool>,
    metadata: ToolMetadata,
    usage_stats: UsageStats,
}

/// Usage statistics for adaptive discovery
#[derive(Debug, Default)]
struct UsageStats {
    total_calls: u64,
    success_count: u64,
    error_count: u64,
    avg_execution_time_ms: f64,
    last_used: Option<std::time::Instant>,
}

/// AI discovery context for intelligent tool selection
#[derive(Debug, Clone)]
struct DiscoveryContext {
    /// Embeddings of tool descriptions for semantic search
    tool_embeddings: HashMap<String, Vec<f32>>,
    /// Common usage patterns
    usage_patterns: Vec<UsagePattern>,
    /// Agent preferences learned over time
    agent_preferences: HashMap<AgentType, Vec<String>>,
}

/// Usage patterns for AI learning
#[derive(Debug, Clone)]
struct UsagePattern {
    /// Sequence of tools commonly used together
    tool_sequence: Vec<String>,
    /// Context in which this pattern appears
    context_tags: Vec<String>,
    /// Success rate of this pattern
    success_rate: f64,
}

impl UnifiedToolRegistry {
    fn new() -> Self {
        Self {
            tools: HashMap::new(),
            by_category: HashMap::new(),
            by_capability: HashMap::new(),
            discovery_context: None,
        }
    }
    
    /// Register a self-registering tool
    pub fn register(tool: Arc<dyn SelfRegisteringTool>) -> Result<(), AppError> {
        let mut registry = UNIFIED_REGISTRY.write()
            .map_err(|_| AppError::InternalServerErrorGeneric("Failed to acquire registry lock".into()))?;
        
        let metadata = tool.metadata();
        let name = metadata.name.clone();
        
        // Check for duplicates
        if registry.tools.contains_key(&name) {
            return Err(AppError::InvalidInput(format!("Tool '{}' already registered", name)));
        }
        
        // Index by category
        registry.by_category
            .entry(metadata.category)
            .or_default()
            .push(name.clone());
        
        // Index by capabilities
        for capability in &metadata.capabilities {
            let cap_key = format!("{}:{}", capability.action, capability.target);
            registry.by_capability
                .entry(cap_key)
                .or_default()
                .push(name.clone());
        }
        
        // Store the tool
        registry.tools.insert(name.clone(), RegisteredTool {
            implementation: tool,
            metadata,
            usage_stats: UsageStats::default(),
        });
        
        info!("Registered tool: {}", name);
        Ok(())
    }
    
    /// Get tools available to a specific agent with security checks
    pub fn get_tools_for_agent(agent: AgentType) -> Vec<ToolMetadata> {
        let registry = match UNIFIED_REGISTRY.read() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        
        registry.tools.values()
            .filter(|tool| {
                tool.metadata.security_policy.allowed_agents.contains(&agent)
            })
            .map(|tool| tool.metadata.clone())
            .collect()
    }
    
    /// AI-powered tool discovery based on task description
    pub async fn discover_tools(
        agent: AgentType,
        task_description: &str,
        context: &HashMap<String, JsonValue>,
    ) -> Result<Vec<ToolRecommendation>, AppError> {
        let registry = UNIFIED_REGISTRY.read()
            .map_err(|_| AppError::InternalServerErrorGeneric("Failed to acquire registry lock".into()))?;
        
        // Get tools this agent can access
        let accessible_tools: Vec<_> = registry.tools.values()
            .filter(|tool| tool.metadata.security_policy.allowed_agents.contains(&agent))
            .collect();
        
        // Use AI to analyze task and recommend tools
        let mut recommendations = Vec::new();
        
        // TODO: Implement actual AI-powered discovery using embeddings and LLM
        // For now, use rule-based matching on capabilities and keywords
        
        let task_lower = task_description.to_lowercase();
        
        for tool in accessible_tools {
            let mut relevance_score = 0.0;
            
            // Check capabilities
            for capability in &tool.metadata.capabilities {
                if task_lower.contains(&capability.action) && 
                   task_lower.contains(&capability.target) {
                    relevance_score += 0.5;
                }
            }
            
            // Check tags
            for tag in &tool.metadata.tags {
                if task_lower.contains(tag) {
                    relevance_score += 0.3;
                }
            }
            
            // Check when_to_use description
            if tool.metadata.when_to_use.to_lowercase()
                .split_whitespace()
                .any(|word| task_lower.contains(word)) {
                relevance_score += 0.2;
            }
            
            if relevance_score > 0.0 {
                recommendations.push(ToolRecommendation {
                    tool_name: tool.metadata.name.clone(),
                    relevance_score,
                    reasoning: format!(
                        "Matched capabilities and context for: {}",
                        task_description
                    ),
                    usage_example: tool.metadata.usage_examples.first().cloned(),
                });
            }
        }
        
        // Sort by relevance
        recommendations.sort_by(|a, b| b.relevance_score.partial_cmp(&a.relevance_score).unwrap());
        
        Ok(recommendations)
    }
    
    /// Execute a tool with security checks and monitoring
    pub async fn execute_tool(
        agent: AgentType,
        tool_name: &str,
        params: &ToolParams,
        session_dek: &SessionDek,
        context: ExecutionContext,
    ) -> Result<ToolResult, ToolError> {
        // Get tool with security check
        let tool = {
            let registry = UNIFIED_REGISTRY.read()
                .map_err(|_| ToolError::ExecutionFailed("Registry lock failed".into()))?;
            
            let registered_tool = registry.tools.get(tool_name)
                .ok_or_else(|| ToolError::ExecutionFailed(format!("Tool '{}' not found", tool_name)))?;
            
            // Security check
            if !registered_tool.metadata.security_policy.allowed_agents.contains(&agent) {
                return Err(ToolError::ExecutionFailed(
                    format!("Agent {:?} not authorized to use tool '{}'", agent, tool_name)
                ));
            }
            
            // Check required capabilities
            for required in &registered_tool.metadata.security_policy.required_capabilities {
                if !context.agent_capabilities.contains(required) {
                    return Err(ToolError::ExecutionFailed(
                        format!("Missing required capability: {}", required)
                    ));
                }
            }
            
            registered_tool.implementation.clone()
        };
        
        // Filter parameters to only include those expected by the tool
        let filtered_params = Self::filter_tool_parameters(tool_name, params, &context)?;
        
        // Update usage stats
        let start_time = std::time::Instant::now();
        
        // Execute with monitoring
        let result = tool.execute(&filtered_params, session_dek).await;
        
        // Update stats
        {
            let mut registry = UNIFIED_REGISTRY.write()
                .map_err(|_| ToolError::ExecutionFailed("Registry lock failed".into()))?;
            
            if let Some(registered_tool) = registry.tools.get_mut(tool_name) {
                registered_tool.usage_stats.total_calls += 1;
                match &result {
                    Ok(_) => registered_tool.usage_stats.success_count += 1,
                    Err(_) => registered_tool.usage_stats.error_count += 1,
                }
                registered_tool.usage_stats.last_used = Some(start_time);
                
                // Update average execution time
                let exec_time = start_time.elapsed().as_millis() as f64;
                let stats = &mut registered_tool.usage_stats;
                stats.avg_execution_time_ms = 
                    (stats.avg_execution_time_ms * (stats.total_calls - 1) as f64 + exec_time) 
                    / stats.total_calls as f64;
            }
        }
        
        // Audit if required
        let audit_level = if let Ok(registry) = UNIFIED_REGISTRY.read() {
            registry.tools.get(tool_name).map(|tool| tool.metadata.security_policy.audit_level)
        } else {
            None
        };
        
        if let Some(audit_level) = audit_level {
            match audit_level {
                AuditLevel::Basic => {
                    info!("Tool executed: {} by {:?}", tool_name, agent);
                }
                AuditLevel::Detailed => {
                    info!("Tool executed: {} by {:?} with params: {:?}", 
                        tool_name, agent, params);
                }
                AuditLevel::Full => {
                    info!("Tool executed: {} by {:?} with params: {:?}, result: {:?}", 
                        tool_name, agent, params, result);
                }
                AuditLevel::None => {}
            }
        }
        
        result
    }
    
    /// Filter tool parameters to only include those expected by the tool's schema
    /// Removes null values and parameters not defined in the tool's input schema
    fn filter_tool_parameters(tool_name: &str, params: &ToolParams, context: &ExecutionContext) -> Result<ToolParams, ToolError> {
        let tool_schema = {
            let registry = UNIFIED_REGISTRY.read()
                .map_err(|_| ToolError::ExecutionFailed("Registry lock failed".into()))?;
            
            let registered_tool = registry.tools.get(tool_name)
                .ok_or_else(|| ToolError::ExecutionFailed(format!("Tool '{}' not found", tool_name)))?;
            
            registered_tool.implementation.input_schema()
        };
        
        // Extract expected parameters from the schema
        let expected_params = if let Some(properties) = tool_schema.get("properties").and_then(|p| p.as_object()) {
            properties.keys().map(|k| k.as_str()).collect::<std::collections::HashSet<_>>()
        } else {
            // If no properties defined, allow all parameters
            return Ok(params.clone());
        };
        
        // Filter the input parameters
        let mut filtered = serde_json::Map::new();
        
        if let Some(params_obj) = params.as_object() {
            for (key, value) in params_obj {
                // Only include parameters that:
                // 1. Are expected by the tool's schema
                // 2. Are not null
                if expected_params.contains(key.as_str()) && !value.is_null() {
                    filtered.insert(key.clone(), value.clone());
                }
            }
        }
        
        // Auto-add user_id if it's expected but missing
        if expected_params.contains("user_id") && !filtered.contains_key("user_id") {
            // Extract user_id from the execution context
            filtered.insert("user_id".to_string(), serde_json::Value::String(context.user_id.to_string()));
        }
        
        Ok(serde_json::Value::Object(filtered))
    }
    
    /// Get a specific tool by name (for compatibility with old ToolRegistry API)
    pub fn get_tool(tool_name: &str) -> Result<Arc<dyn SelfRegisteringTool>, AppError> {
        let registry = UNIFIED_REGISTRY.read()
            .map_err(|_| AppError::InternalServerErrorGeneric("Failed to acquire registry lock".into()))?;
        
        registry.tools.get(tool_name)
            .map(|registered_tool| registered_tool.implementation.clone())
            .ok_or_else(|| AppError::InternalServerErrorGeneric(format!("Tool '{}' not found", tool_name)))
    }
    
    /// Get all registered tools (for compatibility with old ToolRegistry API)
    pub fn get_all_tools() -> Vec<Arc<dyn SelfRegisteringTool>> {
        let registry = match UNIFIED_REGISTRY.read() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        
        registry.tools.values()
            .map(|registered_tool| registered_tool.implementation.clone())
            .collect()
    }
    
    /// List all tool names (for compatibility with old ToolRegistry API)
    pub fn list_all_tool_names() -> Vec<String> {
        let registry = match UNIFIED_REGISTRY.read() {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        
        registry.tools.keys().cloned().collect()
    }
    
    /// Clear the registry (for testing only)
    #[cfg(test)]
    pub fn clear() -> Result<(), AppError> {
        let mut registry = UNIFIED_REGISTRY.write()
            .map_err(|_| AppError::InternalServerErrorGeneric("Failed to acquire registry lock".into()))?;
        
        registry.tools.clear();
        registry.by_category.clear();
        registry.by_capability.clear();
        registry.discovery_context = None;
        
        info!("Cleared unified tool registry");
        Ok(())
    }
    
    /// Register a tool if it doesn't already exist (idempotent registration)
    pub fn register_if_not_exists(tool: Arc<dyn SelfRegisteringTool>) -> Result<bool, AppError> {
        let mut registry = UNIFIED_REGISTRY.write()
            .map_err(|_| AppError::InternalServerErrorGeneric("Failed to acquire registry lock".into()))?;
        
        let metadata = tool.metadata();
        let name = metadata.name.clone();
        
        // Check if already registered
        if registry.tools.contains_key(&name) {
            info!("Tool '{}' already registered, skipping", name);
            return Ok(false);
        }
        
        // Index by category
        registry.by_category
            .entry(metadata.category)
            .or_default()
            .push(name.clone());
        
        // Index by capabilities
        for capability in &metadata.capabilities {
            let cap_key = format!("{}:{}", capability.action, capability.target);
            registry.by_capability
                .entry(cap_key)
                .or_default()
                .push(name.clone());
        }
        
        // Store the tool
        registry.tools.insert(name.clone(), RegisteredTool {
            implementation: tool,
            metadata,
            usage_stats: UsageStats::default(),
        });
        
        info!("Registered tool: {}", name);
        Ok(true)
    }
}

/// Tool recommendation from AI discovery
#[derive(Debug, Clone, Serialize)]
pub struct ToolRecommendation {
    pub tool_name: String,
    pub relevance_score: f64,
    pub reasoning: String,
    pub usage_example: Option<ToolExample>,
}

/// Execution context for security and monitoring
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub request_id: Uuid,
    pub agent_capabilities: Vec<String>,
    pub user_id: Uuid,
    pub session_id: Option<Uuid>,
    pub parent_tool: Option<String>,
}

/// Macro for easy tool registration
// Note: This macro is commented out to avoid duplicate definition
// Use the register_tool! macro from the example_self_registering module instead
// #[macro_export]
// macro_rules! register_tool {
//     ($tool_type:ty) => {{
//         use $crate::services::agentic::unified_tool_registry::{UnifiedToolRegistry, SelfRegisteringTool};
//         use std::sync::Arc;
//         
//         let tool = Arc::new(<$tool_type>::new()) as Arc<dyn SelfRegisteringTool>;
//         UnifiedToolRegistry::register(tool)
//             .expect(&format!("Failed to register tool: {}", stringify!($tool_type)));
//     }};
// }

/// Initialize all tools at startup
pub fn initialize_tool_registry() -> Result<(), AppError> {
    info!("Initializing unified tool registry");
    
    // Tools will self-register using the macro
    // Example: register_tool!(AnalyzeTextSignificanceTool);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_capability_matching() {
        let capability = ToolCapability {
            action: "analyze".to_string(),
            target: "narrative text".to_string(),
            context: Some("for significance".to_string()),
        };
        
        let cap_key = format!("{}:{}", capability.action, capability.target);
        assert_eq!(cap_key, "analyze:narrative text");
    }
    
    #[test]
    fn test_security_policy_creation() {
        let policy = ToolSecurityPolicy {
            allowed_agents: vec![AgentType::Orchestrator, AgentType::Strategic],
            required_capabilities: vec!["narrative_analysis".to_string()],
            rate_limit: Some(RateLimit {
                calls_per_minute: 60,
                calls_per_hour: 1000,
                burst_size: 10,
            }),
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false,
                allowed_scopes: vec!["narratives".to_string()],
            },
            audit_level: AuditLevel::Detailed,
        };
        
        assert_eq!(policy.allowed_agents.len(), 2);
        assert!(policy.allowed_agents.contains(&AgentType::Orchestrator));
    }
}