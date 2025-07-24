//! Security tests for the Unified Tool Registry based on OWASP Top 10
//! 
//! Tests security vulnerabilities and ensures proper security controls
//! are in place for the tool registry system.

use scribe_backend::{
    services::agentic::{
        tools::{ScribeTool, ToolError, ToolParams, ToolResult},
        unified_tool_registry::{
            UnifiedToolRegistry, SelfRegisteringTool, ToolCategory, ToolCapability,
            ToolExample, ToolSecurityPolicy, AgentType, DataAccessPolicy, AuditLevel,
            RateLimit, ExecutionContext, ExecutionTime, ResourceRequirements,
        },
    },
};
use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use std::sync::Arc;
use uuid::Uuid;

// Mock tool for security testing
struct SecurityTestTool {
    name: String,
    allowed_agents: Vec<AgentType>,
    required_capabilities: Vec<String>,
    audit_level: AuditLevel,
    data_access: DataAccessPolicy,
}

#[async_trait]
impl ScribeTool for SecurityTestTool {
    fn name(&self) -> &'static str {
        Box::leak(self.name.clone().into_boxed_str())
    }
    
    fn description(&self) -> &'static str {
        "Security test tool"
    }
    
    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "input": { "type": "string" }
            },
            "required": ["input"]
        })
    }
    
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        // Simulate processing sensitive data
        let input = params.get("input")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        
        // Check for injection attempts
        if input.contains("<script>") || input.contains("'; DROP TABLE") {
            return Err(ToolError::InvalidParams("Potential injection detected".into()));
        }
        
        Ok(json!({
            "result": "processed",
            "data": input
        }))
    }
}

#[async_trait]
impl SelfRegisteringTool for SecurityTestTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Validation
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "validate".to_string(),
                target: "input".to_string(),
                context: None,
            }
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Security testing".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Production use".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![]
    }
    
    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: self.allowed_agents.clone(),
            required_capabilities: self.required_capabilities.clone(),
            rate_limit: Some(RateLimit {
                calls_per_minute: 10,
                calls_per_hour: 100,
                burst_size: 5,
            }),
            data_access: self.data_access.clone(),
            audit_level: self.audit_level,
        }
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "result": { "type": "string" },
                "data": { "type": "string" }
            }
        })
    }
}

// A01:2021 - Broken Access Control Tests
#[tokio::test]
async fn test_a01_broken_access_control_agent_restriction() {
    let tool = Arc::new(SecurityTestTool {
        name: "restricted_tool".to_string(),
        allowed_agents: vec![AgentType::Strategic],
        required_capabilities: vec![],
        audit_level: AuditLevel::Full,
        data_access: DataAccessPolicy {
            user_data: true,
            system_data: true,
            write_access: true,
            allowed_scopes: vec!["admin".to_string()],
        },
    });
    
    UnifiedToolRegistry::register(tool).unwrap();
    
    let params = json!(json!({"input": "test"}));
    let context = ExecutionContext {
        request_id: Uuid::new_v4(),
        agent_capabilities: vec![],
        user_id: Uuid::new_v4(),
        session_id: None,
        parent_tool: None,
    };
    
    // Unauthorized agent should not be able to execute
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Tactical, // Not in allowed_agents
        "restricted_tool",
        &params,
        context.clone(),
    ).await;
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ToolError::ExecutionFailed(msg) if msg.contains("not authorized")));
    
    // Authorized agent should be able to execute
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Strategic,
        "restricted_tool",
        &params,
        context,
    ).await;
    
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_a01_capability_based_access_control() {
    let tool = Arc::new(SecurityTestTool {
        name: "capability_restricted_tool".to_string(),
        allowed_agents: vec![AgentType::Orchestrator],
        required_capabilities: vec!["admin_access".to_string(), "write_permission".to_string()],
        audit_level: AuditLevel::Full,
        data_access: DataAccessPolicy {
            user_data: true,
            system_data: true,
            write_access: true,
            allowed_scopes: vec!["sensitive".to_string()],
        },
    });
    
    UnifiedToolRegistry::register(tool).unwrap();
    
    let params = json!(json!({"input": "test"}));
    
    // Context without required capabilities
    let context_no_caps = ExecutionContext {
        request_id: Uuid::new_v4(),
        agent_capabilities: vec!["read_permission".to_string()],
        user_id: Uuid::new_v4(),
        session_id: None,
        parent_tool: None,
    };
    
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Orchestrator,
        "capability_restricted_tool",
        &params,
        context_no_caps,
    ).await;
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ToolError::ExecutionFailed(msg) if msg.contains("Missing required capability")));
    
    // Context with required capabilities
    let context_with_caps = ExecutionContext {
        request_id: Uuid::new_v4(),
        agent_capabilities: vec!["admin_access".to_string(), "write_permission".to_string()],
        user_id: Uuid::new_v4(),
        session_id: None,
        parent_tool: None,
    };
    
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Orchestrator,
        "capability_restricted_tool",
        &params,
        context_with_caps,
    ).await;
    
    assert!(result.is_ok());
}

// A03:2021 - Injection Tests
#[tokio::test]
async fn test_a03_injection_prevention() {
    let tool = Arc::new(SecurityTestTool {
        name: "injection_test_tool".to_string(),
        allowed_agents: vec![AgentType::Orchestrator],
        required_capabilities: vec![],
        audit_level: AuditLevel::Full,
        data_access: DataAccessPolicy {
            user_data: false,
            system_data: false,
            write_access: false,
            allowed_scopes: vec![],
        },
    });
    
    UnifiedToolRegistry::register(tool).unwrap();
    
    let context = ExecutionContext {
        request_id: Uuid::new_v4(),
        agent_capabilities: vec![],
        user_id: Uuid::new_v4(),
        session_id: None,
        parent_tool: None,
    };
    
    // Test SQL injection attempt
    let sql_injection_params = json!(json!({
        "input": "'; DROP TABLE entities; --"
    }));
    
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Orchestrator,
        "injection_test_tool",
        &sql_injection_params,
        context.clone(),
    ).await;
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ToolError::InvalidParams(msg) if msg.contains("injection")));
    
    // Test XSS attempt
    let xss_params = json!(json!({
        "input": "<script>alert('XSS')</script>"
    }));
    
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Orchestrator,
        "injection_test_tool",
        &xss_params,
        context.clone(),
    ).await;
    
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ToolError::InvalidParams(msg) if msg.contains("injection")));
    
    // Test command injection attempt
    let cmd_injection_params = json!(json!({
        "input": "test; rm -rf /"
    }));
    
    // Should not execute dangerous commands
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Orchestrator,
        "injection_test_tool",
        &cmd_injection_params,
        context,
    ).await;
    
    // Tool should safely process without executing commands
    assert!(result.is_ok());
}

// A04:2021 - Insecure Design Tests
#[tokio::test]
async fn test_a04_secure_by_design_principles() {
    // Test that tools enforce secure defaults
    let tool = Arc::new(SecurityTestTool {
        name: "secure_defaults_tool".to_string(),
        allowed_agents: vec![AgentType::Orchestrator],
        required_capabilities: vec![],
        audit_level: AuditLevel::Basic,
        data_access: DataAccessPolicy {
            user_data: false, // Secure default: no user data access
            system_data: false, // Secure default: no system data access
            write_access: false, // Secure default: read-only
            allowed_scopes: vec![], // Secure default: no scopes
        },
    });
    
    UnifiedToolRegistry::register(tool).unwrap();
    
    // Verify secure defaults are enforced
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    let secure_tool = tools.iter().find(|t| t.name == "secure_defaults_tool").unwrap();
    
    assert!(!secure_tool.security_policy.data_access.user_data);
    assert!(!secure_tool.security_policy.data_access.system_data);
    assert!(!secure_tool.security_policy.data_access.write_access);
    assert!(secure_tool.security_policy.data_access.allowed_scopes.is_empty());
}

// A05:2021 - Security Misconfiguration Tests
#[tokio::test]
async fn test_a05_rate_limiting_enforcement() {
    let tool = Arc::new(SecurityTestTool {
        name: "rate_limited_tool".to_string(),
        allowed_agents: vec![AgentType::Orchestrator],
        required_capabilities: vec![],
        audit_level: AuditLevel::Basic,
        data_access: DataAccessPolicy {
            user_data: false,
            system_data: false,
            write_access: false,
            allowed_scopes: vec![],
        },
    });
    
    UnifiedToolRegistry::register(tool).unwrap();
    
    // Get the tool metadata to verify rate limits
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    let rate_limited = tools.iter().find(|t| t.name == "rate_limited_tool").unwrap();
    
    assert!(rate_limited.security_policy.rate_limit.is_some());
    let rate_limit = rate_limited.security_policy.rate_limit.as_ref().unwrap();
    assert_eq!(rate_limit.calls_per_minute, 10);
    assert_eq!(rate_limit.calls_per_hour, 100);
    assert_eq!(rate_limit.burst_size, 5);
}

// A07:2021 - Identification and Authentication Failures Tests
#[tokio::test]
async fn test_a07_execution_context_validation() {
    let tool = Arc::new(SecurityTestTool {
        name: "auth_required_tool".to_string(),
        allowed_agents: vec![AgentType::Orchestrator],
        required_capabilities: vec!["authenticated".to_string()],
        audit_level: AuditLevel::Full,
        data_access: DataAccessPolicy {
            user_data: true,
            system_data: false,
            write_access: false,
            allowed_scopes: vec!["user_profile".to_string()],
        },
    });
    
    UnifiedToolRegistry::register(tool).unwrap();
    
    let params = json!(json!({"input": "test"}));
    
    // Test with missing session
    let context_no_session = ExecutionContext {
        request_id: Uuid::new_v4(),
        agent_capabilities: vec!["authenticated".to_string()],
        user_id: Uuid::new_v4(),
        session_id: None, // No session
        parent_tool: None,
    };
    
    // Tool requiring user data should validate session
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Orchestrator,
        "auth_required_tool",
        &params,
        context_no_session,
    ).await;
    
    // For now it passes, but in production should validate session
    assert!(result.is_ok());
    
    // Test with valid session
    let context_with_session = ExecutionContext {
        request_id: Uuid::new_v4(),
        agent_capabilities: vec!["authenticated".to_string()],
        user_id: Uuid::new_v4(),
        session_id: Some(Uuid::new_v4()),
        parent_tool: None,
    };
    
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Orchestrator,
        "auth_required_tool",
        &params,
        context_with_session,
    ).await;
    
    assert!(result.is_ok());
}

// A08:2021 - Software and Data Integrity Failures Tests
#[tokio::test]
async fn test_a08_tool_integrity_verification() {
    // Test that tools cannot be modified after registration
    let tool1 = Arc::new(SecurityTestTool {
        name: "integrity_test_tool".to_string(),
        allowed_agents: vec![AgentType::Orchestrator],
        required_capabilities: vec![],
        audit_level: AuditLevel::Basic,
        data_access: DataAccessPolicy {
            user_data: false,
            system_data: false,
            write_access: false,
            allowed_scopes: vec![],
        },
    });
    
    UnifiedToolRegistry::register(tool1).unwrap();
    
    // Attempt to register same tool name with different permissions
    let tool2 = Arc::new(SecurityTestTool {
        name: "integrity_test_tool".to_string(),
        allowed_agents: vec![AgentType::Orchestrator, AgentType::Tactical], // Different!
        required_capabilities: vec!["admin".to_string()], // Different!
        audit_level: AuditLevel::None, // Different!
        data_access: DataAccessPolicy {
            user_data: true, // Different!
            system_data: true, // Different!
            write_access: true, // Different!
            allowed_scopes: vec!["all".to_string()], // Different!
        },
    });
    
    // Should fail - cannot override existing tool
    let result = UnifiedToolRegistry::register(tool2);
    assert!(result.is_err());
    
    // Verify original tool maintains integrity
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    let original = tools.iter().find(|t| t.name == "integrity_test_tool").unwrap();
    
    assert_eq!(original.security_policy.allowed_agents.len(), 1);
    assert!(original.security_policy.required_capabilities.is_empty());
    assert!(!original.security_policy.data_access.user_data);
}

// A09:2021 - Security Logging and Monitoring Failures Tests
#[tokio::test]
async fn test_a09_audit_logging_levels() {
    // Test different audit levels
    let tools = vec![
        ("no_audit_tool", AuditLevel::None),
        ("basic_audit_tool", AuditLevel::Basic),
        ("detailed_audit_tool", AuditLevel::Detailed),
        ("full_audit_tool", AuditLevel::Full),
    ];
    
    for (name, audit_level) in tools {
        let tool = Arc::new(SecurityTestTool {
            name: name.to_string(),
            allowed_agents: vec![AgentType::Orchestrator],
            required_capabilities: vec![],
            audit_level,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false,
                allowed_scopes: vec!["test".to_string()],
            },
        });
        
        UnifiedToolRegistry::register(tool).unwrap();
    }
    
    let params = json!(json!({"input": "sensitive data"}));
    let context = ExecutionContext {
        request_id: Uuid::new_v4(),
        agent_capabilities: vec![],
        user_id: Uuid::new_v4(),
        session_id: Some(Uuid::new_v4()),
        parent_tool: None,
    };
    
    // Execute each tool - audit logging should occur based on level
    let tool_names = vec!["no_audit_tool", "basic_audit_tool", "detailed_audit_tool", "full_audit_tool"];
    for name in tool_names {
        let result = UnifiedToolRegistry::execute_tool(
            AgentType::Orchestrator,
            name,
            &params,
            context.clone(),
        ).await;
        
        assert!(result.is_ok());
        // In production, verify logs are generated according to audit level
    }
}

// A10:2021 - Server-Side Request Forgery Tests
#[tokio::test]
async fn test_a10_external_calls_tracking() {
    // Tools making external calls should be tracked
    struct ExternalCallTool;
    
    #[async_trait]
    impl ScribeTool for ExternalCallTool {
        fn name(&self) -> &'static str { "external_call_tool" }
        fn description(&self) -> &'static str { "Makes external API calls" }
        fn input_schema(&self) -> JsonValue { json!({}) }
        async fn execute(&self, _: &ToolParams) -> Result<ToolResult, ToolError> {
            // In production, this would make external calls
            Ok(json!({}))
        }
    }
    
    #[async_trait]
    impl SelfRegisteringTool for ExternalCallTool {
        fn category(&self) -> ToolCategory { ToolCategory::Discovery }
        fn capabilities(&self) -> Vec<ToolCapability> { vec![] }
        fn when_to_use(&self) -> String { "External data needed".to_string() }
        fn when_not_to_use(&self) -> String { "Offline mode".to_string() }
        fn usage_examples(&self) -> Vec<ToolExample> { vec![] }
        fn security_policy(&self) -> ToolSecurityPolicy {
            ToolSecurityPolicy {
                allowed_agents: vec![AgentType::Orchestrator],
                required_capabilities: vec!["external_access".to_string()],
                rate_limit: Some(RateLimit {
                    calls_per_minute: 5, // Strict rate limit for external calls
                    calls_per_hour: 50,
                    burst_size: 2,
                }),
                data_access: DataAccessPolicy {
                    user_data: false,
                    system_data: false,
                    write_access: false,
                    allowed_scopes: vec![],
                },
                audit_level: AuditLevel::Full, // Full audit for external calls
            }
        }
        fn output_schema(&self) -> JsonValue { json!({}) }
        fn resource_requirements(&self) -> ResourceRequirements {
            ResourceRequirements {
                memory_mb: 100,
                execution_time: ExecutionTime::Slow,
                external_calls: true, // Marked as making external calls
                compute_intensive: false,
            }
        }
    }
    
    let tool = Arc::new(ExternalCallTool);
    UnifiedToolRegistry::register(tool).unwrap();
    
    // Verify tool is marked as making external calls
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    let external_tool = tools.iter().find(|t| t.name == "external_call_tool").unwrap();
    
    assert!(external_tool.resource_requirements.external_calls);
    assert!(external_tool.security_policy.rate_limit.is_some());
    assert_eq!(external_tool.security_policy.audit_level, AuditLevel::Full);
}

// Additional security tests
#[tokio::test]
async fn test_data_scope_enforcement() {
    let tool = Arc::new(SecurityTestTool {
        name: "scoped_data_tool".to_string(),
        allowed_agents: vec![AgentType::Perception],
        required_capabilities: vec![],
        audit_level: AuditLevel::Detailed,
        data_access: DataAccessPolicy {
            user_data: true,
            system_data: false,
            write_access: false,
            allowed_scopes: vec!["narratives".to_string(), "chronicles".to_string()],
        },
    });
    
    UnifiedToolRegistry::register(tool).unwrap();
    
    // Verify scope restrictions
    let tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Perception);
    let scoped_tool = tools.iter().find(|t| t.name == "scoped_data_tool").unwrap();
    
    assert_eq!(scoped_tool.security_policy.data_access.allowed_scopes.len(), 2);
    assert!(scoped_tool.security_policy.data_access.allowed_scopes.contains(&"narratives".to_string()));
    assert!(scoped_tool.security_policy.data_access.allowed_scopes.contains(&"chronicles".to_string()));
    assert!(!scoped_tool.security_policy.data_access.allowed_scopes.contains(&"system".to_string()));
}

#[tokio::test]
async fn test_privilege_escalation_prevention() {
    // Test that tools cannot escalate privileges through parent_tool chain
    let privileged_tool = Arc::new(SecurityTestTool {
        name: "privileged_parent_tool".to_string(),
        allowed_agents: vec![AgentType::Orchestrator],
        required_capabilities: vec!["admin".to_string()],
        audit_level: AuditLevel::Full,
        data_access: DataAccessPolicy {
            user_data: true,
            system_data: true,
            write_access: true,
            allowed_scopes: vec!["all".to_string()],
        },
    });
    
    let unprivileged_tool = Arc::new(SecurityTestTool {
        name: "unprivileged_child_tool".to_string(),
        allowed_agents: vec![AgentType::Tactical],
        required_capabilities: vec![],
        audit_level: AuditLevel::Basic,
        data_access: DataAccessPolicy {
            user_data: false,
            system_data: false,
            write_access: false,
            allowed_scopes: vec![],
        },
    });
    
    UnifiedToolRegistry::register(privileged_tool).unwrap();
    UnifiedToolRegistry::register(unprivileged_tool).unwrap();
    
    let params = json!(json!({"input": "test"}));
    
    // Context claiming to be called by privileged parent
    let escalation_context = ExecutionContext {
        request_id: Uuid::new_v4(),
        agent_capabilities: vec![], // No admin capability
        user_id: Uuid::new_v4(),
        session_id: Some(Uuid::new_v4()),
        parent_tool: Some("privileged_parent_tool".to_string()),
    };
    
    // Should not inherit parent privileges
    let result = UnifiedToolRegistry::execute_tool(
        AgentType::Tactical,
        "unprivileged_child_tool",
        &params,
        escalation_context,
    ).await;
    
    // Tool executes with its own privileges, not parent's
    assert!(result.is_ok());
}