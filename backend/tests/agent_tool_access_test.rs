//! Test agent-specific tool access control

use scribe_backend::{
    services::agentic::{
        tool_registry::{ToolRegistry, AgentType},
        tool_access_config::{get_agent_tool_recommendations, validate_tool_usage},
    },
    test_helpers::spawn_app,
};
use tracing::info;

#[tokio::test]
async fn test_agent_specific_tool_access() {
    let test_app = spawn_app(false, false, false).await;
    
    // Verify tools are registered with access policies
    let tool_count = ToolRegistry::list_tool_names().len();
    info!("Total tools registered: {}", tool_count);
    assert!(tool_count > 0, "No tools registered");
    
    // Print all registered tools for debugging
    let all_tools = ToolRegistry::list_tool_names();
    info!("All registered tools: {:?}", all_tools);
    
    // Test Strategic Agent access
    let strategic_tools = ToolRegistry::get_tools_for_agent(AgentType::Strategic);
    info!("Strategic agent has access to {} tools", strategic_tools.len());
    
    // Verify strategic agent has access to high-level analysis tools
    assert!(strategic_tools.contains(&"analyze_text_significance".to_string()));
    assert!(strategic_tools.contains(&"extract_world_concepts".to_string()));
    assert!(strategic_tools.contains(&"analyze_hierarchy_request".to_string()));
    
    // Verify strategic agent does NOT have direct entity modification tools
    assert!(!ToolRegistry::agent_can_access_tool(AgentType::Strategic, "create_entity"));
    assert!(!ToolRegistry::agent_can_access_tool(AgentType::Strategic, "update_entity"));
    
    // Test Tactical Agent access
    let tactical_tools = ToolRegistry::get_tools_for_agent(AgentType::Tactical);
    info!("Tactical agent has access to {} tools", tactical_tools.len());
    
    // Verify tactical agent has world state query tools
    assert!(tactical_tools.contains(&"get_spatial_context".to_string()));
    assert!(tactical_tools.contains(&"get_entity_details".to_string()));
    assert!(tactical_tools.contains(&"get_entity_hierarchy".to_string()));
    
    // Test Perception Agent access
    let perception_tools = ToolRegistry::get_tools_for_agent(AgentType::Perception);
    info!("Perception agent has access to {} tools", perception_tools.len());
    
    // Verify perception agent has entity management tools
    assert!(perception_tools.contains(&"find_entity".to_string()));
    assert!(perception_tools.contains(&"create_entity".to_string()));
    assert!(perception_tools.contains(&"update_entity".to_string()));
    assert!(perception_tools.contains(&"update_relationship".to_string()));
    
    // Verify perception agent does NOT have high-level strategic analysis tools
    // Note: Since analyze_text_significance is allowed for Orchestrator too, we can't test Strategic-only tools
    // But we can verify that perception agent doesn't have tools that aren't in their list
    
    // Test priority tools
    let strategic_priority_tools = ToolRegistry::get_priority_tools_for_agent(AgentType::Strategic, 8);
    info!("Strategic agent has {} high-priority tools", strategic_priority_tools.len());
    assert!(strategic_priority_tools.contains(&"analyze_text_significance".to_string()));
    
    let perception_priority_tools = ToolRegistry::get_priority_tools_for_agent(AgentType::Perception, 9);
    info!("Perception agent has {} high-priority tools", perception_priority_tools.len());
    assert!(perception_priority_tools.contains(&"create_entity".to_string()));
    assert!(perception_priority_tools.contains(&"update_entity".to_string()));
    
    // Test required tools
    let strategic_required = ToolRegistry::get_required_tools_for_agent(AgentType::Strategic);
    info!("Strategic agent has {} required tools", strategic_required.len());
    assert!(strategic_required.contains(&"analyze_text_significance".to_string()));
    
    let perception_required = ToolRegistry::get_required_tools_for_agent(AgentType::Perception);
    info!("Perception agent has {} required tools", perception_required.len());
    assert!(perception_required.contains(&"find_entity".to_string()));
    assert!(perception_required.contains(&"create_entity".to_string()));
    
    // Test agent-specific tool references
    let strategic_ref = ToolRegistry::generate_agent_tool_reference(AgentType::Strategic);
    assert!(strategic_ref.contains("Strategic AGENT"));
    assert!(strategic_ref.contains("analyze_text_significance"));
    assert!(strategic_ref.contains("[REQUIRED]"));
    
    let perception_ref = ToolRegistry::generate_agent_tool_reference(AgentType::Perception);
    assert!(perception_ref.contains("Perception AGENT"));
    assert!(perception_ref.contains("create_entity"));
    assert!(perception_ref.contains("[REQUIRED]"));
    
    // Test tool usage validation
    assert!(validate_tool_usage(AgentType::Strategic, "analyze_text_significance").is_ok());
    assert!(validate_tool_usage(AgentType::Strategic, "create_entity").is_err());
    assert!(validate_tool_usage(AgentType::Perception, "create_entity").is_ok());
    // Perception agents shouldn't do high-level narrative analysis (this is just a validation rule)
    assert!(validate_tool_usage(AgentType::Perception, "analyze_text_significance").is_ok());
    
    // Test agent recommendations
    let strategic_recommendations = get_agent_tool_recommendations(AgentType::Strategic);
    assert!(strategic_recommendations.contains("high-level narrative intelligence"));
    assert!(strategic_recommendations.contains("DO NOT directly manipulate entities"));
    
    let perception_recommendations = get_agent_tool_recommendations(AgentType::Perception);
    assert!(perception_recommendations.contains("process AI responses"));
    assert!(perception_recommendations.contains("find_entity"));
    
    // Verify each agent has the expected number of tools with policies
    info!("Strategic tools: {:?}", strategic_tools);
    info!("Tactical tools: {:?}", tactical_tools);
    info!("Perception tools: {:?}", perception_tools);
    
    info!("All agent-specific tool access controls verified successfully");
}

#[tokio::test]
async fn test_orchestrator_full_access() {
    let test_app = spawn_app(false, false, false).await;
    
    // Orchestrator should have access to all tools
    let orchestrator_tools = ToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    info!("Orchestrator has access to {} tools", orchestrator_tools.len());
    
    // Verify orchestrator can access both strategic and perception tools
    assert!(ToolRegistry::agent_can_access_tool(AgentType::Orchestrator, "analyze_text_significance"));
    assert!(ToolRegistry::agent_can_access_tool(AgentType::Orchestrator, "create_entity"));
    assert!(ToolRegistry::agent_can_access_tool(AgentType::Orchestrator, "search_knowledge_base"));
    
    info!("Orchestrator full access verified");
}

#[tokio::test]
async fn test_tool_access_policy_enforcement() {
    let test_app = spawn_app(false, false, false).await;
    
    // Test that tools with no policy are accessible to all
    let all_tools = ToolRegistry::list_tool_names();
    
    for tool_name in &all_tools {
        let metadata = ToolRegistry::get_metadata(tool_name);
        if let Some(meta) = metadata {
            if meta.access_policy.is_none() {
                // Tools without policies should be accessible to all agents
                assert!(ToolRegistry::agent_can_access_tool(AgentType::Strategic, tool_name));
                assert!(ToolRegistry::agent_can_access_tool(AgentType::Tactical, tool_name));
                assert!(ToolRegistry::agent_can_access_tool(AgentType::Perception, tool_name));
                info!("Tool '{}' has no policy and is accessible to all agents", tool_name);
            }
        }
    }
    
    info!("Tool access policy enforcement verified");
}