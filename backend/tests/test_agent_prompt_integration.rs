//! Test that agents include tool references in their prompts

use scribe_backend::{
    services::{
        agentic::{
            tool_registry::{ToolRegistry, AgentType},
        },
    },
    test_helpers::spawn_app,
};
use tracing::info;

#[tokio::test]
async fn test_tool_references_match_agent_access() {
    let _test_app = spawn_app(false, false, false).await;
    
    // Get tool references for each agent type
    let strategic_ref = ToolRegistry::generate_agent_tool_reference(AgentType::Strategic);
    let perception_ref = ToolRegistry::generate_agent_tool_reference(AgentType::Perception);
    let tactical_ref = ToolRegistry::generate_agent_tool_reference(AgentType::Tactical);
    
    info!("Strategic agent tool reference preview: {}", &strategic_ref[..500.min(strategic_ref.len())]);
    
    // Verify Strategic agent has appropriate tools
    assert!(strategic_ref.contains("AVAILABLE TOOLS FOR STRATEGIC AGENT"));
    assert!(strategic_ref.contains("analyze_text_significance"));
    assert!(strategic_ref.contains("extract_world_concepts"));
    assert!(!strategic_ref.contains("create_entity"), 
        "Strategic agent should not have entity creation tools");
    
    // Verify Perception agent has appropriate tools
    assert!(perception_ref.contains("AVAILABLE TOOLS FOR PERCEPTION AGENT"));
    assert!(perception_ref.contains("create_entity"));
    assert!(perception_ref.contains("update_entity"));
    assert!(perception_ref.contains("find_entity"));
    assert!(!perception_ref.contains("analyze_text_significance"),
        "Perception agent should not have high-level analysis tools");
    
    // Verify Tactical agent has appropriate tools
    assert!(tactical_ref.contains("AVAILABLE TOOLS FOR TACTICAL AGENT"));
    assert!(tactical_ref.contains("find_entity"));
    assert!(tactical_ref.contains("get_spatial_context"));
    assert!(!tactical_ref.contains("create_entity"),
        "Tactical agent should not have entity creation tools");
    
    // Verify all have proper formatting
    assert!(strategic_ref.contains("When to use:"));
    assert!(strategic_ref.contains("Performance:"));
    assert!(perception_ref.contains("Input Format:"));
    assert!(perception_ref.contains("Output:"));
    assert!(tactical_ref.contains("HIGH PRIORITY TOOLS") || 
            tactical_ref.contains("MEDIUM PRIORITY TOOLS") ||
            tactical_ref.contains("LOW PRIORITY TOOLS"));
}

#[tokio::test] 
async fn test_tool_reference_generation_performance() {
    let _test_app = spawn_app(false, false, false).await;
    
    // Test that tool reference generation is reasonably fast
    let start = std::time::Instant::now();
    
    for _ in 0..10 {
        let _ = ToolRegistry::generate_agent_tool_reference(AgentType::Strategic);
        let _ = ToolRegistry::generate_agent_tool_reference(AgentType::Tactical);
        let _ = ToolRegistry::generate_agent_tool_reference(AgentType::Perception);
        let _ = ToolRegistry::generate_agent_tool_reference(AgentType::Orchestrator);
    }
    
    let duration = start.elapsed();
    
    // Should complete 40 generations in under 100ms
    assert!(duration.as_millis() < 100, 
        "Tool reference generation too slow: {:?}", duration);
}

#[tokio::test]
async fn test_tool_reference_content_quality() {
    let _test_app = spawn_app(false, false, false).await;
    
    // Test Strategic agent reference
    let strategic_ref = ToolRegistry::generate_agent_tool_reference(AgentType::Strategic);
    
    // Check for agent-specific guidance
    assert!(strategic_ref.contains("STRATEGIC LAYER") || strategic_ref.contains("DIRECTOR"));
    assert!(strategic_ref.contains("high-level narrative intelligence"));
    
    // Check for priority grouping
    assert!(strategic_ref.contains("PRIORITY TOOLS"));
    
    // Check for usage examples
    assert!(strategic_ref.contains("Examples:") || strategic_ref.contains("When to use:"));
    
    // Check for performance characteristics
    assert!(strategic_ref.contains("Performance:"));
    assert!(strategic_ref.contains("External Calls:"));
    assert!(strategic_ref.contains("Modifies State:"));
    
    // Check for tool summary
    assert!(strategic_ref.contains("TOOL SUMMARY"));
    assert!(strategic_ref.contains("Total Available Tools:"));
    assert!(strategic_ref.contains("Required Tools:"));
    
    // Test that [REQUIRED] tools are marked
    if strategic_ref.contains("analyze_text_significance") {
        assert!(strategic_ref.contains("[REQUIRED]"));
    }
}

#[tokio::test]
async fn test_agent_tool_count() {
    let _test_app = spawn_app(false, false, false).await;
    
    // Get tools for each agent type
    let strategic_tools = ToolRegistry::get_tools_for_agent(AgentType::Strategic);
    let tactical_tools = ToolRegistry::get_tools_for_agent(AgentType::Tactical);
    let perception_tools = ToolRegistry::get_tools_for_agent(AgentType::Perception);
    let orchestrator_tools = ToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    
    info!("Tool counts - Strategic: {}, Tactical: {}, Perception: {}, Orchestrator: {}",
        strategic_tools.len(), tactical_tools.len(), perception_tools.len(), orchestrator_tools.len());
    
    // Verify reasonable tool counts - based on actual counts from log
    assert!(strategic_tools.len() >= 10, "Strategic agent should have at least 10 tools");
    assert!(tactical_tools.len() >= 14, "Tactical agent should have at least 14 tools");
    assert!(perception_tools.len() >= 17, "Perception agent should have at least 17 tools");
    assert!(orchestrator_tools.len() >= 11, "Orchestrator should have access to many tools");
    
    // Verify proper separation - Perception should have most tools
    assert!(strategic_tools.len() < perception_tools.len(), 
        "Strategic agent should have fewer tools than Perception");
    assert!(perception_tools.len() >= tactical_tools.len(), 
        "Perception agent should have at least as many tools as Tactical");
}