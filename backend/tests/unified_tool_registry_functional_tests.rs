//! Functional tests for the Unified Tool Registry
//! 
//! Tests the core functionality of tool registration, discovery, execution,
//! and the self-registration pattern.

use scribe_backend::{
    auth::session_dek::SessionDek,
    errors::AppError,
    services::agentic::{
        tools::{ScribeTool, ToolError, ToolParams, ToolResult},
        unified_tool_registry::{
            UnifiedToolRegistry, SelfRegisteringTool, ToolCategory, ToolCapability,
            ToolExample, ToolSecurityPolicy, AgentType, DataAccessPolicy, AuditLevel,
            ExecutionContext,
        },
        ai_tool_discovery::{
            AiToolDiscoveryService, TaskContext, WorkflowPhase,
            AgentToolDiscovery,
        },
    },
    test_helpers::MockAiClient,
};
use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use std::sync::Arc;
use uuid::Uuid;

// Mock tool for testing
pub struct MockAnalysisTool {
    name: String,
    allowed_agents: Vec<AgentType>,
}

impl MockAnalysisTool {
    pub fn new(name: String) -> Self {
        Self {
            name,
            allowed_agents: vec![AgentType::Orchestrator, AgentType::Strategic],
        }
    }
}

#[async_trait]
impl ScribeTool for MockAnalysisTool {
    fn name(&self) -> &'static str {
        Box::leak(self.name.clone().into_boxed_str())
    }
    
    fn description(&self) -> &'static str {
        "Mock analysis tool for testing"
    }
    
    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "data": { "type": "string" }
            },
            "required": ["data"]
        })
    }
    
    async fn execute(&self, params: &ToolParams, _session_dek: Option<&SessionDek>) -> Result<ToolResult, ToolError> {
        Ok(json!({
            "analyzed": params.get("data").unwrap_or(&json!(""))
        }))
    }
}

#[async_trait]
impl SelfRegisteringTool for MockAnalysisTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "analyze".to_string(),
                target: "data".to_string(),
                description: "Analyzes data".to_string(),
                constraints: vec![],
            }
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when data analysis is needed".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Don't use for data modification".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Analyzing user behavior".to_string(),
                params: json!({"data": "user_activity_log"}),
                expected_behavior: "Returns analysis results".to_string(),
            }
        ]
    }
    
    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: self.allowed_agents.clone(),
            data_access: DataAccessPolicy::ReadOnly,
            audit_level: AuditLevel::Standard,
            rate_limit: Some(100),
            requires_approval: false,
        }
    }
}

#[tokio::test]
async fn test_tool_registration_and_discovery() {
    // Create and register a mock tool
    let tool = Arc::new(MockAnalysisTool::new("test_analysis_tool".into()));
    
    // Register the tool
    let result = UnifiedToolRegistry::register(tool.clone());
    assert!(result.is_ok());
    
    // Verify orchestrator can see the tool
    let orchestrator_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    assert!(orchestrator_tools.iter().any(|t| t.name == "test_analysis_tool"));
    
    // Verify tactical agent cannot see the tool (not in allowed_agents)
    let tactical_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Tactical);
    assert!(!tactical_tools.iter().any(|t| t.name == "test_analysis_tool"));
}

#[tokio::test]
async fn test_duplicate_tool_registration() {
    // Create two tools with the same name
    let tool1 = Arc::new(MockAnalysisTool::new("duplicate_tool".into()));
    let tool2 = Arc::new(MockAnalysisTool::new("duplicate_tool".into()));
    
    // First registration should succeed
    let result1 = UnifiedToolRegistry::register(tool1);
    assert!(result1.is_ok());
    
    // Second registration should fail
    let result2 = UnifiedToolRegistry::register(tool2);
    assert!(result2.is_err());
}

#[tokio::test]
async fn test_ai_powered_discovery() {
    // Register tools with different capabilities
    let analysis_tool = Arc::new(MockAnalysisTool::new("ai_discovery_analysis".into()));
    UnifiedToolRegistry::register(analysis_tool).unwrap();
    
    // Test discovery
    let mut context = std::collections::HashMap::new();
    context.insert("workflow_phase".to_string(), json!("analysis"));
    
    let recommendations = UnifiedToolRegistry::discover_tools(
        AgentType::Orchestrator,
        "I need to analyze user behavior patterns",
        &context,
    ).await;
    
    assert!(recommendations.is_ok());
    let tools = recommendations.unwrap();
    assert!(!tools.is_empty());
}

#[tokio::test]
async fn test_tool_security_enforcement() {
    // Create a tool with restricted access
    struct SecureExecutionTool;
    
    #[async_trait]
    impl ScribeTool for SecureExecutionTool {
        fn name(&self) -> &'static str { "secure_execution_tool" }
        fn description(&self) -> &'static str { "Tool with security restrictions" }
        fn input_schema(&self) -> JsonValue { json!({}) }
        async fn execute(&self, _: &ToolParams, _: Option<&SessionDek>) -> Result<ToolResult, ToolError> {
            Ok(json!({"executed": true}))
        }
    }
    
    #[async_trait]
    impl SelfRegisteringTool for SecureExecutionTool {
        fn category(&self) -> ToolCategory { ToolCategory::Infrastructure }
        fn capabilities(&self) -> Vec<ToolCapability> { vec![] }
        fn when_to_use(&self) -> String { "Infrastructure operations".to_string() }
        fn when_not_to_use(&self) -> String { "General purposes".to_string() }
        fn usage_examples(&self) -> Vec<ToolExample> { vec![] }
        fn security_policy(&self) -> ToolSecurityPolicy {
            ToolSecurityPolicy {
                allowed_agents: vec![AgentType::Orchestrator],
                data_access: DataAccessPolicy::ReadWrite,
                audit_level: AuditLevel::Detailed,
                rate_limit: Some(10),
                requires_approval: true,
            }
        }
    }
    
    // Register the tool
    UnifiedToolRegistry::register(Arc::new(SecureExecutionTool)).unwrap();
    
    // Verify only orchestrator can see it
    let orchestrator_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    assert!(orchestrator_tools.iter().any(|t| t.name == "secure_execution_tool"));
    
    let tactical_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Tactical);
    assert!(!tactical_tools.iter().any(|t| t.name == "secure_execution_tool"));
}

#[tokio::test]
async fn test_tool_discovery_by_category() {
    // Register multiple tools in different categories
    let tool1 = Arc::new(MockAnalysisTool::new("category_test_1".into()));
    let tool2 = Arc::new(MockAnalysisTool::new("category_test_2".into()));
    
    UnifiedToolRegistry::register(tool1).unwrap();
    UnifiedToolRegistry::register(tool2).unwrap();
    
    // Get all analysis tools for orchestrator
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    let analysis_tools: Vec<_> = tools.iter()
        .filter(|t| t.category == ToolCategory::Analysis)
        .collect();
    
    assert!(analysis_tools.len() >= 2);
}

#[tokio::test]
async fn test_ai_discovery_service_integration() {
    // Create mock AI client
    let ai_client = Arc::new(MockAiClient::new());
    ai_client.add_response(r#"{
        "recommended_tools": [
            {
                "tool_name": "test_tool",
                "relevance_score": 0.9,
                "reasoning": "Highly relevant for the task"
            }
        ]
    }"#.to_string());
    
    let discovery_service = AiToolDiscoveryService::new(ai_client);
    
    // Create task context
    let task_context = TaskContext {
        agent_type: AgentType::Strategic,
        task_description: "Analyze narrative progression".to_string(),
        workflow_phase: WorkflowPhase::Planning,
        available_context: json!({}),
        previous_tools_used: vec![],
        constraints: vec![],
    };
    
    // Test discovery
    let recommendations = discovery_service.discover_tools_for_task(&task_context).await;
    assert!(recommendations.is_ok());
}

#[tokio::test]
async fn test_self_registration_pattern() {
    // Create a tool that registers itself
    struct SelfRegisteringTestTool;
    
    #[async_trait]
    impl ScribeTool for SelfRegisteringTestTool {
        fn name(&self) -> &'static str { "self_registering_test" }
        fn description(&self) -> &'static str { "Tests self-registration" }
        fn input_schema(&self) -> JsonValue { json!({}) }
        async fn execute(&self, _: &ToolParams, _: Option<&SessionDek>) -> Result<ToolResult, ToolError> {
            Ok(json!({}))
        }
    }
    
    #[async_trait]
    impl SelfRegisteringTool for SelfRegisteringTestTool {
        fn category(&self) -> ToolCategory { ToolCategory::Testing }
        fn capabilities(&self) -> Vec<ToolCapability> { vec![] }
        fn when_to_use(&self) -> String { "Testing".to_string() }
        fn when_not_to_use(&self) -> String { "Production".to_string() }
        fn usage_examples(&self) -> Vec<ToolExample> { vec![] }
        fn security_policy(&self) -> ToolSecurityPolicy {
            ToolSecurityPolicy::default()
        }
    }
    
    // Register and verify
    let tool = Arc::new(SelfRegisteringTestTool);
    assert!(UnifiedToolRegistry::register(tool).is_ok());
    
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    assert!(tools.iter().any(|t| t.name == "self_registering_test"));
}

#[tokio::test]
async fn test_tool_dependency_resolution() {
    // Create tools with dependencies
    struct BaseTool;
    struct DependentTool;
    
    #[async_trait]
    impl ScribeTool for BaseTool {
        fn name(&self) -> &'static str { "base_tool" }
        fn description(&self) -> &'static str { "Base tool" }
        fn input_schema(&self) -> JsonValue { json!({}) }
        async fn execute(&self, _: &ToolParams, _: Option<&SessionDek>) -> Result<ToolResult, ToolError> {
            Ok(json!({}))
        }
    }
    
    #[async_trait]
    impl SelfRegisteringTool for BaseTool {
        fn category(&self) -> ToolCategory { ToolCategory::Infrastructure }
        fn capabilities(&self) -> Vec<ToolCapability> { vec![] }
        fn when_to_use(&self) -> String { "Base operations".to_string() }
        fn when_not_to_use(&self) -> String { "Never".to_string() }
        fn usage_examples(&self) -> Vec<ToolExample> { vec![] }
        fn security_policy(&self) -> ToolSecurityPolicy {
            ToolSecurityPolicy::default()
        }
    }
    
    #[async_trait]
    impl ScribeTool for DependentTool {
        fn name(&self) -> &'static str { "dependent_tool" }
        fn description(&self) -> &'static str { "Tool with dependencies" }
        fn input_schema(&self) -> JsonValue { json!({}) }
        async fn execute(&self, _: &ToolParams, _: Option<&SessionDek>) -> Result<ToolResult, ToolError> {
            Ok(json!({}))
        }
    }
    
    #[async_trait]
    impl SelfRegisteringTool for DependentTool {
        fn category(&self) -> ToolCategory { ToolCategory::Analysis }
        fn capabilities(&self) -> Vec<ToolCapability> { vec![] }
        fn when_to_use(&self) -> String { "Test".to_string() }
        fn when_not_to_use(&self) -> String { "Never".to_string() }
        fn usage_examples(&self) -> Vec<ToolExample> { vec![] }
        fn security_policy(&self) -> ToolSecurityPolicy {
            ToolSecurityPolicy::default()
        }
        fn dependencies(&self) -> Vec<String> {
            vec!["base_tool".to_string()]
        }
    }
    
    // Register tools
    UnifiedToolRegistry::register(Arc::new(BaseTool)).unwrap();
    UnifiedToolRegistry::register(Arc::new(DependentTool)).unwrap();
    
    // Verify both are available
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    assert!(tools.iter().any(|t| t.name == "base_tool"));
    assert!(tools.iter().any(|t| t.name == "dependent_tool"));
}