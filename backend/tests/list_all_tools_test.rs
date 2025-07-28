//! Test to list all registered tools in the unified registry

use scribe_backend::{
    services::agentic::unified_tool_registry::{UnifiedToolRegistry, AgentType},
    test_helpers::spawn_app,
};

#[tokio::test]
async fn list_all_registered_tools() {
    let test_app = spawn_app(false, false, false).await;
    
    // Tools are already initialized by spawn_app, no need to initialize again
    
    // Get all tools from the unified registry
    let all_tools = UnifiedToolRegistry::list_all_tool_names();
    println!("\n=== ALL {} REGISTERED TOOLS IN UNIFIED REGISTRY ===", all_tools.len());
    
    // Sort for consistent output
    let mut sorted_tools = all_tools.clone();
    sorted_tools.sort();
    
    // Print basic list first
    println!("\n--- Tool Names ---");
    for (i, tool) in sorted_tools.iter().enumerate() {
        println!("{}. {}", i + 1, tool);
    }
    
    // Get tools by agent type to show access control
    println!("\n--- Tools by Agent Type ---");
    
    let orchestrator_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    let strategic_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Strategic);
    let tactical_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Tactical);
    let perception_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Perception);
    
    println!("\nOrchestrator Agent Tools ({}):", orchestrator_tools.len());
    for (i, tool) in orchestrator_tools.iter().enumerate() {
        println!("  {}. {} - Category: {:?} - Version: {}", 
                 i + 1, tool.name, tool.category, tool.version);
    }
    
    println!("\nStrategic Agent Tools ({}):", strategic_tools.len());
    for (i, tool) in strategic_tools.iter().enumerate() {
        println!("  {}. {} - Category: {:?} - Version: {}", 
                 i + 1, tool.name, tool.category, tool.version);
    }
    
    println!("\nTactical Agent Tools ({}):", tactical_tools.len());
    for (i, tool) in tactical_tools.iter().enumerate() {
        println!("  {}. {} - Category: {:?} - Version: {}", 
                 i + 1, tool.name, tool.category, tool.version);
    }
    
    println!("\nPerception Agent Tools ({}):", perception_tools.len());
    for (i, tool) in perception_tools.iter().enumerate() {
        println!("  {}. {} - Category: {:?} - Version: {}", 
                 i + 1, tool.name, tool.category, tool.version);
    }
    
    // Show detailed metadata for a few sample tools
    println!("\n--- Sample Tool Details ---");
    let sample_tools = sorted_tools.iter().take(3).collect::<Vec<_>>();
    for tool_name in sample_tools {
        if let Ok(tool) = UnifiedToolRegistry::get_tool(tool_name) {
            let metadata = tool.metadata();
            println!("\nTool: {}", metadata.name);
            println!("  Description: {}", metadata.description);
            println!("  Category: {:?}", metadata.category);
            println!("  Capabilities: {}", metadata.capabilities.len());
            for (i, cap) in metadata.capabilities.iter().enumerate() {
                println!("    {}. {} {} ({})", 
                         i + 1, cap.action, cap.target, 
                         cap.context.as_ref().unwrap_or(&"no context".to_string()));
            }
            println!("  Dependencies: {:?}", metadata.dependencies);
            println!("  Tags: {:?}", metadata.tags);
            println!("  Resource Requirements: Memory {}MB, Time: {:?}", 
                     metadata.resource_requirements.memory_mb,
                     metadata.resource_requirements.execution_time);
        }
    }
    
    // Verify we have the expected number of tools (based on our migration)
    // Currently implemented:
    // - 6 entity CRUD tools (FindEntityTool, GetEntityDetailsTool, CreateEntityTool, UpdateEntityTool, DeleteEntityTool, QuerySpatialTypesTool)
    // - 1 entity resolution tool (EntityResolutionTool)
    // - 2 spatial interaction tools (GetSpatialContextTool, MoveEntityTool)
    // - 3 relationship interaction tools (UpdateRelationshipTool, CreateRelationshipTool, DeleteRelationshipTool)
    // - 3 AI-powered tools (AnalyzeHierarchyRequestTool, SuggestHierarchyPromotionTool, UpdateSalienceTool)
    // - 1 hierarchy tool (GetEntityHierarchyTool)
    // - 1 chronicle tool (QueryChronicleEventsTool)
    // - 2 lorebook tools (QueryLorebookTool, ManageLorebookTool)
    // - 2 inventory tools (QueryInventoryTool, ManageInventoryTool)
    // - 5 narrative tools (AnalyzeTextSignificanceTool, CreateChronicleEventTool, ExtractTemporalEventsTool, ExtractWorldConceptsTool, SearchKnowledgeBaseTool)
    // = 26 total tools currently implemented
    assert!(all_tools.len() >= 26, "Expected at least 26 implemented tools, got {}", all_tools.len());
    println!("\n✓ Successfully verified {} tools are registered in the unified registry", all_tools.len());
}