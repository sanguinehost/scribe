//! Test enhanced tool reference generation for agents

use scribe_backend::{
    services::agentic::{
        tool_registry::{ToolRegistry, AgentType},
    },
    test_helpers::spawn_app,
};
use tracing::info;

#[tokio::test]
async fn test_strategic_agent_tool_reference() {
    let test_app = spawn_app(false, false, false).await;
    
    // Generate tool reference for Strategic agent
    let reference = ToolRegistry::generate_agent_tool_reference(AgentType::Strategic);
    
    info!("Strategic Agent Tool Reference:\n{}", reference);
    
    // Verify the reference contains expected sections
    assert!(reference.contains("STRATEGIC LAYER (\"DIRECTOR\") TOOL USAGE GUIDE"));
    assert!(reference.contains("HIGH PRIORITY TOOLS"));
    assert!(reference.contains("analyze_text_significance"));
    assert!(reference.contains("[REQUIRED]"));
    assert!(reference.contains("When to use:"));
    assert!(reference.contains("Performance:"));
    assert!(reference.contains("TOOL SUMMARY"));
    
    // Verify Strategic agent doesn't have entity modification tools
    assert!(!reference.contains("`create_entity`"));
    assert!(!reference.contains("`update_entity`"));
}

#[tokio::test]
async fn test_tactical_agent_tool_reference() {
    let test_app = spawn_app(false, false, false).await;
    
    // Generate tool reference for Tactical agent
    let reference = ToolRegistry::generate_agent_tool_reference(AgentType::Tactical);
    
    info!("Tactical Agent Tool Reference:\n{}", reference);
    
    // Verify the reference contains expected sections
    assert!(reference.contains("TACTICAL LAYER (\"STAGE MANAGER\") TOOL USAGE GUIDE"));
    assert!(reference.contains("find_entity"));
    assert!(reference.contains("get_spatial_context"));
    assert!(reference.contains("When to use:"));
    assert!(reference.contains("Examples:"));
    
    // Verify Tactical agent doesn't have entity modification tools
    assert!(!reference.contains("`create_entity`"));
    assert!(!reference.contains("`update_entity`"));
}

#[tokio::test]
async fn test_perception_agent_tool_reference() {
    let test_app = spawn_app(false, false, false).await;
    
    // Generate tool reference for Perception agent
    let reference = ToolRegistry::generate_agent_tool_reference(AgentType::Perception);
    
    info!("Perception Agent Tool Reference:\n{}", reference);
    
    // Verify the reference contains expected sections
    assert!(reference.contains("PERCEPTION LAYER (\"WORLD STATE OBSERVER\") TOOL USAGE GUIDE"));
    assert!(reference.contains("create_entity"));
    assert!(reference.contains("update_entity"));
    assert!(reference.contains("update_relationship"));
    assert!(reference.contains("[REQUIRED]"));
    assert!(reference.contains("Input Format:"));
    assert!(reference.contains("Output:"));
    
    // Verify Perception agent has world state modification tools
    assert!(reference.contains("`find_entity`"));
    assert!(reference.contains("`create_entity`"));
    assert!(reference.contains("`update_entity`"));
}

#[tokio::test]
async fn test_tool_reference_formatting() {
    let test_app = spawn_app(false, false, false).await;
    
    // Test a sample reference for proper formatting
    let reference = ToolRegistry::generate_agent_tool_reference(AgentType::Orchestrator);
    
    // Check for priority sections
    assert!(reference.contains("HIGH PRIORITY TOOLS") || 
            reference.contains("MEDIUM PRIORITY TOOLS") || 
            reference.contains("LOW PRIORITY TOOLS"));
    
    // Check for tool documentation elements
    assert!(reference.contains("Description:"));
    assert!(reference.contains("When to use:"));
    assert!(reference.contains("Performance:"));
    assert!(reference.contains("External Calls:"));
    assert!(reference.contains("Modifies State:"));
    
    // Check for summary section
    assert!(reference.contains("TOOL SUMMARY"));
    assert!(reference.contains("Total Available Tools:"));
    assert!(reference.contains("Required Tools:"));
}

#[tokio::test]
async fn test_tool_reference_examples() {
    let test_app = spawn_app(false, false, false).await;
    
    // Generate reference and check for usage examples
    let reference = ToolRegistry::generate_agent_tool_reference(AgentType::Perception);
    
    // Some tools should have examples
    let tools_with_examples = ["find_entity", "create_entity", "update_entity"];
    
    for tool in &tools_with_examples {
        if reference.contains(&format!("`{}`", tool)) {
            // Tool exists, check if it has example section nearby
            let tool_section = reference.find(&format!("`{}`", tool));
            if let Some(pos) = tool_section {
                let section_end = pos + 1000; // Check next 1000 chars
                let section = &reference[pos..reference.len().min(section_end)];
                
                // Check for either Examples section or usage information
                assert!(section.contains("Examples:") || 
                        section.contains("When to use:") ||
                        section.contains("Input Format:"),
                        "Tool {} should have usage information", tool);
            }
        }
    }
}