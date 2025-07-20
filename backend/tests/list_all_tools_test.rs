//! Test to list all registered tools

use scribe_backend::{
    services::agentic::tool_registry::ToolRegistry,
    test_helpers::spawn_app,
};

#[tokio::test]
async fn list_all_registered_tools() {
    let test_app = spawn_app(false, false, false).await;
    
    let all_tools = ToolRegistry::list_tool_names();
    println!("\nAll {} registered tools:", all_tools.len());
    
    // Sort for consistent output
    let mut sorted_tools = all_tools.clone();
    sorted_tools.sort();
    
    for (i, tool) in sorted_tools.iter().enumerate() {
        let metadata = ToolRegistry::get_metadata(tool);
        if let Some(meta) = metadata {
            println!("{}. {} - Category: {:?}", i + 1, tool, meta.category);
        } else {
            println!("{}. {} - No metadata", i + 1, tool);
        }
    }
}