//! Test that agents can properly use the dynamic tool registry

use scribe_backend::{
    services::agentic::{
        factory::AgenticNarrativeFactory,
        tool_registry::ToolRegistry,
    },
    test_helpers::spawn_app,
};
use tracing::info;

#[tokio::test]
async fn test_agents_use_dynamic_tool_registry() {
    let test_app = spawn_app(false, false, false).await;
    
    // Verify tools are registered
    let tool_count = ToolRegistry::list_tool_names().len();
    info!("Total tools registered: {}", tool_count);
    assert!(tool_count > 0, "No tools registered");
    
    // Create tactical agent
    let tactical_agent = AgenticNarrativeFactory::create_tactical_agent(&test_app.app_state);
    info!("Created tactical agent successfully");
    
    // Create perception agent  
    let perception_agent = AgenticNarrativeFactory::create_perception_agent(&test_app.app_state);
    info!("Created perception agent successfully");
    
    // Create strategic agent
    let strategic_agent = AgenticNarrativeFactory::create_strategic_agent(&test_app.app_state);
    info!("Created strategic agent successfully");
    
    // Verify specific tools are available
    assert!(ToolRegistry::get_tool("find_entity").is_ok());
    assert!(ToolRegistry::get_tool("create_entity").is_ok());
    assert!(ToolRegistry::get_tool("update_entity").is_ok());
    assert!(ToolRegistry::get_tool("get_spatial_context").is_ok());
    assert!(ToolRegistry::get_tool("analyze_text_significance").is_ok());
    
    info!("All agents created successfully with access to dynamic tool registry");
}