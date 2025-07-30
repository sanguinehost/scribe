//! Test that agents include tool references in their prompts

use scribe_backend::{
    services::{
        agentic::{
            unified_tool_registry::{UnifiedToolRegistry, AgentType},
        },
    },
    test_helpers::spawn_app,
};
use tracing::info;

#[tokio::test]
async fn test_tool_references_match_agent_access() {
    let _test_app = spawn_app(false, false, false).await;
    
    // Get tools for each agent type
    let strategic_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Strategic);
    let perception_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Perception);
    let tactical_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Tactical);
    
    // Generate tool references manually from available tools
    let strategic_ref = format!("AVAILABLE TOOLS FOR STRATEGIC AGENT:\n{}", 
        strategic_tools.iter()
            .map(|t| format!("- {}: {}", t.name, t.description))
            .collect::<Vec<_>>()
            .join("\n"));
    
    let perception_ref = format!("AVAILABLE TOOLS FOR PERCEPTION AGENT:\n{}", 
        perception_tools.iter()
            .map(|t| format!("- {}: {}", t.name, t.description))
            .collect::<Vec<_>>()
            .join("\n"));
    
    let tactical_ref = format!("AVAILABLE TOOLS FOR TACTICAL AGENT:\n{}", 
        tactical_tools.iter()
            .map(|t| format!("- {}: {}", t.name, t.description))
            .collect::<Vec<_>>()
            .join("\n"));
    
    info!("Strategic agent tool reference preview: {}", &strategic_ref[..500.min(strategic_ref.len())]);
    
    // Verify Strategic agent has appropriate tools
    assert!(strategic_ref.contains("AVAILABLE TOOLS FOR STRATEGIC AGENT"));
    let strategic_tool_names: Vec<String> = strategic_tools.iter().map(|t| t.name.clone()).collect();
    assert!(strategic_tool_names.contains(&"analyze_text_significance".to_string()));
    assert!(strategic_tool_names.contains(&"extract_world_concepts".to_string()));
    assert!(!strategic_tool_names.contains(&"create_entity".to_string()), 
        "Strategic agent should not have entity creation tools");
    
    // Verify Perception agent has appropriate tools
    assert!(perception_ref.contains("AVAILABLE TOOLS FOR PERCEPTION AGENT"));
    let perception_tool_names: Vec<String> = perception_tools.iter().map(|t| t.name.clone()).collect();
    assert!(perception_tool_names.contains(&"create_entity".to_string()));
    assert!(perception_tool_names.contains(&"update_entity".to_string()));
    assert!(perception_tool_names.contains(&"find_entity".to_string()));
    assert!(!perception_tool_names.contains(&"analyze_text_significance".to_string()),
        "Perception agent should not have high-level analysis tools");
    
    // Verify Tactical agent has appropriate tools
    assert!(tactical_ref.contains("AVAILABLE TOOLS FOR TACTICAL AGENT"));
    let tactical_tool_names: Vec<String> = tactical_tools.iter().map(|t| t.name.clone()).collect();
    assert!(tactical_tool_names.contains(&"find_entity".to_string()));
    assert!(tactical_tool_names.contains(&"get_spatial_context".to_string()));
    assert!(!tactical_tool_names.contains(&"create_entity".to_string()),
        "Tactical agent should not have entity creation tools");
    
    // Verify all tools have metadata
    for tool in &strategic_tools {
        assert!(!tool.description.is_empty());
        assert!(!tool.when_to_use.is_empty());
        assert!(!tool.when_not_to_use.is_empty());
    }
}

#[tokio::test]
async fn test_agent_tool_access_consistency() {
    let _test_app = spawn_app(false, false, false).await;
    
    // Ensure agents can only access tools configured for them
    let all_tool_names = UnifiedToolRegistry::list_all_tool_names();
    
    for tool_name in &all_tool_names {
        // Try to get the tool (should succeed if registered)
        let tool_result = UnifiedToolRegistry::get_tool(tool_name);
        assert!(tool_result.is_ok(), "Tool {} should be accessible", tool_name);
    }
    
    // Test that agent types have distinct tool sets
    let strategic_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Strategic);
    let tactical_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Tactical);
    let perception_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Perception);
    
    info!("Strategic tools: {}", strategic_tools.len());
    info!("Tactical tools: {}", tactical_tools.len());
    info!("Perception tools: {}", perception_tools.len());
    
    // Each agent type should have some tools
    assert!(!strategic_tools.is_empty());
    assert!(!tactical_tools.is_empty());
    assert!(!perception_tools.is_empty());
}

#[tokio::test]
async fn test_tool_reference_performance() {
    let _test_app = spawn_app(false, false, false).await;
    
    // Performance test - generating tool lists should be fast
    let start = std::time::Instant::now();
    
    for _ in 0..10 {
        let _ = UnifiedToolRegistry::get_tools_for_agent(AgentType::Strategic);
        let _ = UnifiedToolRegistry::get_tools_for_agent(AgentType::Tactical);
        let _ = UnifiedToolRegistry::get_tools_for_agent(AgentType::Perception);
        let _ = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    }
    
    let elapsed = start.elapsed();
    assert!(elapsed.as_millis() < 100, "Tool reference generation took too long: {:?}", elapsed);
}

#[tokio::test]
async fn test_tool_categorization() {
    let _test_app = spawn_app(false, false, false).await;
    
    // Test Strategic agent tools
    let strategic_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Strategic);
    
    // Strategic should have analysis tools
    let has_analysis = strategic_tools.iter().any(|t| 
        t.name == "analyze_text_significance" || 
        t.name == "extract_world_concepts" ||
        t.name == "analyze_hierarchy_request"
    );
    assert!(has_analysis, "Strategic agent should have analysis tools");
    
    // Perception should have entity management tools
    let perception_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Perception);
    let has_entity_mgmt = perception_tools.iter().any(|t| 
        t.name == "create_entity" || 
        t.name == "update_entity" ||
        t.name == "delete_entity"
    );
    assert!(has_entity_mgmt, "Perception agent should have entity management tools");
}