//! Functional tests for the Unified Tool Registry
//! 
//! Tests the core functionality of tool registration, discovery, execution,
//! and the self-registration pattern.

use scribe_backend::{
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
    should_fail: bool,
}

impl MockAnalysisTool {
    pub fn new(name: String) -> Self {
        Self { name, should_fail: false }
    }
    
    pub fn new_failing(name: String) -> Self {
        Self { name, should_fail: true }
    }
}

#[async_trait]
impl ScribeTool for MockAnalysisTool {
    fn name(&self) -> &'static str {
        Box::leak(self.name.clone().into_boxed_str())
    }
    
    fn description(&self) -> &'static str {
        "Mock tool for testing analysis functionality"
    }
    
    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "text": { "type": "string" }
            },
            "required": ["text"]
        })
    }
    
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        if self.should_fail {
            return Err(ToolError::ExecutionFailed("Mock failure".into()));
        }
        
        Ok(json!({
            "result": "analysis complete",
            "text": params.get("text").unwrap_or(&json!(""))
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
                target: "text".to_string(),
                context: Some("for testing".to_string()),
            }
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when testing tool registry functionality".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use in production".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Testing analysis".to_string(),
                input: json!({"text": "test input"}),
                expected_output: "Analysis result".to_string(),
            }
        ]
    }
    
    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![AgentType::Orchestrator, AgentType::Perception],
            required_capabilities: vec![],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false,
                allowed_scopes: vec!["test".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "result": { "type": "string" },
                "text": { "type": "string" }
            }
        })
    }
}

#[tokio::test]
async fn test_tool_registration() {
    // Clear registry for test isolation
    let tool = Arc::new(MockAnalysisTool::new("test_registration_tool".into()));
    
    // Register tool
    let result = UnifiedToolRegistry::register(tool.clone());
    assert!(result.is_ok());
    
    // Verify tool is accessible
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    assert!(tools.iter().any(|t| t.name == "test_registration_tool"));
}

#[tokio::test]
async fn test_duplicate_registration_fails() {
    let tool1 = Arc::new(MockAnalysisTool::new("duplicate_tool".into()));
    let tool2 = Arc::new(MockAnalysisTool::new("duplicate_tool".into()));
    
    // First registration should succeed
    assert!(UnifiedToolRegistry::register(tool1).is_ok());
    
    // Second registration should fail
    let result = UnifiedToolRegistry::register(tool2);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), AppError::InvalidInput(_)));
}

#[tokio::test]
async fn test_agent_access_control() {
    let tool = Arc::new(MockAnalysisTool::new("agent_restricted_tool".into()));
    UnifiedToolRegistry::register(tool).unwrap();
    
    // Tool allows Orchestrator and Perception agents
    let orchestrator_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    let perception_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Perception);
    let tactical_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Tactical);
    
    assert!(orchestrator_tools.iter().any(|t| t.name == "agent_restricted_tool"));
    assert!(perception_tools.iter().any(|t| t.name == "agent_restricted_tool"));
    assert!(!tactical_tools.iter().any(|t| t.name == "agent_restricted_tool"));
}

#[tokio::test]
async fn test_tool_execution_with_security() {
    let tool = Arc::new(MockAnalysisTool::new("secure_execution_tool".into()));
    UnifiedToolRegistry::register(tool).unwrap();
    
    let params = json!({
        "text": "test content"
    });
    
    let context = ExecutionContext {
        request_id: Uuid::new_v4(),
        agent_capabilities: vec![],
        user_id: Uuid::new_v4(),
        session_id: Some(Uuid::new_v4()),
        parent_tool: None,
    };
    
    // Orchestrator should be able to execute
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Orchestrator,
        "secure_execution_tool",
        &params,
        context.clone(),
    ).await;
    assert!(result.is_ok());
    
    // Tactical agent should not be able to execute
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Tactical,
        "secure_execution_tool",
        &params,
        context,
    ).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_tool_discovery_by_category() {
    // Register multiple tools
    let tool1 = Arc::new(MockAnalysisTool::new("category_test_1".into()));
    let tool2 = Arc::new(MockAnalysisTool::new("category_test_2".into()));
    
    UnifiedToolRegistry::register(tool1).unwrap();
    UnifiedToolRegistry::register(tool2).unwrap();
    
    // Get all analysis tools for orchestrator
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    let analysis_tools: Vec<_> = tools.iter()
        .filter(|t| matches!(t.category, ToolCategory::Analysis))
        .collect();
    
    assert!(analysis_tools.len() >= 2);
}

#[tokio::test]
async fn test_tool_discovery_by_capability() {
    let tool = Arc::new(MockAnalysisTool::new("capability_search_tool".into()));
    UnifiedToolRegistry::register(tool).unwrap();
    
    let context = std::collections::HashMap::new();
    
    // Search for tools that can "analyze text"
    let recommendations = UnifiedToolRegistry::discover_tools(
        AgentType::Orchestrator,
        "I need to analyze text for testing purposes",
        &context,
    ).await.unwrap();
    
    assert!(recommendations.iter().any(|r| r.tool_name == "capability_search_tool"));
}

#[tokio::test]
async fn test_tool_execution_tracking() {
    let tool = Arc::new(MockAnalysisTool::new("tracking_test_tool".into()));
    UnifiedToolRegistry::register(tool).unwrap();
    
    let params = json!({"text": "test"});
    let context = ExecutionContext {
        request_id: Uuid::new_v4(),
        agent_capabilities: vec![],
        user_id: Uuid::new_v4(),
        session_id: None,
        parent_tool: None,
    };
    
    // Execute tool multiple times
    for _ in 0..3 {
        let _ = UnifiedToolRegistry::execute_tool(
            AgentType::Orchestrator,
            "tracking_test_tool",
            &params,
            context.clone(),
        ).await;
    }
    
    // TODO: Add method to retrieve usage stats and verify
    // For now, we just verify execution doesn't panic with tracking
}

#[tokio::test]
async fn test_tool_error_handling() {
    let tool = Arc::new(MockAnalysisTool::new_failing("failing_tool".into()));
    UnifiedToolRegistry::register(tool).unwrap();
    
    let params = json!({"text": "test"});
    let context = ExecutionContext {
        request_id: Uuid::new_v4(),
        agent_capabilities: vec![],
        user_id: Uuid::new_v4(),
        session_id: None,
        parent_tool: None,
    };
    
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Orchestrator,
        "failing_tool",
        &params,
        context,
    ).await;
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ToolError::ExecutionFailed(_)));
}

#[tokio::test]
async fn test_ai_powered_discovery() {
    // Register test tools
    let narrative_tool = Arc::new(MockAnalysisTool::new("narrative_analyzer".into()));
    UnifiedToolRegistry::register(narrative_tool).unwrap();
    
    // Create mock AI client with AI discovery response
    let ai_discovery_response = r#"{
        "recommendations": [
            {
                "tool_name": "narrative_analyzer",
                "relevance_score": 0.9,
                "reasoning": "This tool can analyze narrative text for significance",
                "order": 1
            }
        ],
        "overall_reasoning": "Based on the task requirements, narrative analysis tools are most relevant",
        "suggested_sequence": ["narrative_analyzer"],
        "warnings": []
    }"#;
    
    let ai_client = Arc::new(MockAiClient::new_with_response(ai_discovery_response.to_string()));
    let discovery_service = AiToolDiscoveryService::new(ai_client);
    
    let context = TaskContext {
        workflow_phase: WorkflowPhase::Perception,
        previous_tools: vec![],
        active_entities: vec![],
        recent_events: vec![],
        metadata: json!({}),
    };
    
    // Test discovery
    let result = discovery_service.discover_tools_for_task(
        AgentType::Orchestrator,
        "I need to analyze narrative text for significance",
        &context,
    ).await.unwrap();
    
    // Should have recommendations
    assert!(!result.recommendations.is_empty());
}

#[tokio::test]
async fn test_tool_dependencies() {
    // Create tool with dependencies
    struct DependentTool;
    
    #[async_trait]
    impl ScribeTool for DependentTool {
        fn name(&self) -> &'static str { "dependent_tool" }
        fn description(&self) -> &'static str { "Tool with dependencies" }
        fn input_schema(&self) -> JsonValue { json!({}) }
        async fn execute(&self, _: &ToolParams) -> Result<ToolResult, ToolError> {
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
            ToolSecurityPolicy {
                allowed_agents: vec![AgentType::Orchestrator],
                required_capabilities: vec![],
                rate_limit: None,
                data_access: DataAccessPolicy {
                    user_data: false,
                    system_data: false,
                    write_access: false,
                    allowed_scopes: vec![],
                },
                audit_level: AuditLevel::None,
            }
        }
        fn output_schema(&self) -> JsonValue { json!({}) }
        fn dependencies(&self) -> Vec<String> {
            vec!["prerequisite_tool".to_string()]
        }
    }
    
    let tool = Arc::new(DependentTool);
    UnifiedToolRegistry::register(tool).unwrap();
    
    // Verify dependency is recorded
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    let dependent = tools.iter().find(|t| t.name == "dependent_tool").unwrap();
    assert_eq!(dependent.dependencies, vec!["prerequisite_tool"]);
}

#[tokio::test]
async fn test_orchestrator_specific_discovery() {
    // Register tools for different phases
    let perception_tool = Arc::new(MockAnalysisTool::new("get_world_state".into()));
    let strategy_tool = Arc::new(MockAnalysisTool::new("assess_opportunities".into()));
    
    UnifiedToolRegistry::register(perception_tool).unwrap();
    UnifiedToolRegistry::register(strategy_tool).unwrap();
    
    // Create mock AI client with AI discovery response
    let ai_discovery_response = r#"{
        "recommendations": [
            {
                "tool_name": "get_world_state",
                "relevance_score": 0.9,
                "reasoning": "This tool can provide world state information",
                "order": 1
            }
        ],
        "overall_reasoning": "Perception phase requires world state analysis tools",
        "suggested_sequence": ["get_world_state"],
        "warnings": []
    }"#;
    
    let ai_client = Arc::new(MockAiClient::new_with_response(ai_discovery_response.to_string()));
    let agent_discovery = AgentToolDiscovery::new(ai_client);
    
    let context = TaskContext {
        workflow_phase: WorkflowPhase::Perception,
        previous_tools: vec![],
        active_entities: vec![],
        recent_events: vec![],
        metadata: json!({}),
    };
    
    // Test phase-specific filtering
    let recommendations = agent_discovery.discover_for_orchestrator(
        WorkflowPhase::Perception,
        "Understand current world state",
        &context,
    ).await.unwrap();
    
    // Should prioritize perception tools
    assert!(recommendations.iter().any(|r| r.tool_name.contains("get")));
}

#[tokio::test]
async fn test_tool_metadata_completeness() {
    let tool = Arc::new(MockAnalysisTool::new("metadata_complete_tool".into()));
    let metadata = tool.metadata();
    
    // Verify all required metadata fields are populated
    assert!(!metadata.name.is_empty());
    assert!(!metadata.description.is_empty());
    assert!(!metadata.when_to_use.is_empty());
    assert!(!metadata.when_not_to_use.is_empty());
    assert!(!metadata.capabilities.is_empty());
    assert!(!metadata.usage_examples.is_empty());
    assert!(!metadata.version.is_empty());
    
    // Verify schemas are valid JSON
    assert!(metadata.input_schema.is_object());
    assert!(metadata.output_schema.is_object());
}

#[tokio::test]
async fn test_core_tools_availability() {
    // Verify each agent type has appropriate core tools
    let orchestrator_tools = AgentToolDiscovery::get_core_tools_for_agent(AgentType::Orchestrator);
    let strategic_tools = AgentToolDiscovery::get_core_tools_for_agent(AgentType::Strategic);
    let tactical_tools = AgentToolDiscovery::get_core_tools_for_agent(AgentType::Tactical);
    let perception_tools = AgentToolDiscovery::get_core_tools_for_agent(AgentType::Perception);
    
    // Each agent should have specific core tools
    assert!(!orchestrator_tools.is_empty());
    assert!(!strategic_tools.is_empty());
    assert!(!tactical_tools.is_empty());
    assert!(!perception_tools.is_empty());
    
    // Verify specific tools for each agent
    assert!(orchestrator_tools.contains(&"analyze_text_significance"));
    assert!(strategic_tools.contains(&"assess_narrative_opportunities"));
    assert!(tactical_tools.contains(&"create_entity"));
    assert!(perception_tools.contains(&"get_visible_entities_and_exits"));
}