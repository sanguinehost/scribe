//! Tool Registration Initialization
//!
//! This module handles the registration of all self-registering tools
//! with the unified tool registry during application startup.

use std::sync::Arc;
use tracing::info;

use crate::{
    errors::AppError,
    state::AppState,
};

// Import all tool registration functions
use crate::services::agentic::tools::{
    entity_crud_tools::register_entity_crud_tools,
    spatial_interaction_tools::register_spatial_interaction_tools,
    relationship_interaction_tools::register_relationship_interaction_tools,
    general_interaction_tools::register_general_interaction_tools,
    ai_powered_tools::register_ai_powered_tools,
    hierarchy_tools::register_hierarchy_tools,
    chronicle_tools::register_chronicle_tools,
    lorebook_tools::register_lorebook_tools,
    inventory_tools::register_inventory_tools,
    narrative_tool_wrappers::register_narrative_tools,
};

use crate::services::agentic::entity_resolution_tool::register_entity_resolution_tool;

/// Initialize and register all tools with the unified tool registry
///
/// This function should be called once during application startup after
/// the AppState has been created. It registers all available tools that
/// implement the SelfRegisteringTool trait.
pub fn initialize_all_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    info!("Initializing unified tool registry with all tools");
    
    // For tests, clear the registry first to ensure clean state
    #[cfg(test)]
    {
        use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
        UnifiedToolRegistry::clear()?;
    }
    
    // Register AI-driven entity CRUD tools (5 tools)
    register_entity_crud_tools(app_state.clone())?;
    info!("Registered entity CRUD tools");
    
    // Register AI-driven entity resolution tool (1 tool)
    register_entity_resolution_tool(app_state.clone())?;
    info!("Registered entity resolution tool");
    
    // Register AI-driven spatial interaction tools (2 tools)
    register_spatial_interaction_tools(app_state.clone())?;
    info!("Registered spatial interaction tools");
    
    // Register AI-driven relationship interaction tools (3 tools)
    register_relationship_interaction_tools(app_state.clone())?;
    info!("Registered relationship interaction tools");
    
    // Register AI-driven general interaction tools (1 tool)
    register_general_interaction_tools(app_state.clone())?;
    info!("Registered general interaction tools");
    
    // Register AI-powered analysis tools (3 tools)
    register_ai_powered_tools(app_state.clone())?;
    info!("Registered AI-powered tools");
    
    // Register hierarchy tools (1 tool - GetEntityHierarchyTool only)
    register_hierarchy_tools(app_state.ecs_entity_manager.clone())?;
    info!("Registered hierarchy tools");
    
    // Register chronicle tools (1 tool)
    register_chronicle_tools(app_state.chronicle_service.clone(), app_state.clone())?;
    info!("Registered chronicle tools");
    
    // Register lorebook tools (2 tools)
    register_lorebook_tools(app_state.clone())?;
    info!("Registered lorebook tools");
    
    // Register inventory tools (2 tools)
    register_inventory_tools(app_state.clone())?;
    info!("Registered inventory tools");
    
    // Register narrative tools (5 tools) - AI-driven analysis and creation tools
    register_narrative_tools(app_state.clone())?;
    info!("Registered narrative tools");
    
    // Log total tool counts by agent type
    use crate::services::agentic::unified_tool_registry::{UnifiedToolRegistry, AgentType};
    
    let orchestrator_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Orchestrator);
    let strategic_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Strategic);
    let tactical_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Tactical);
    let perception_tools = UnifiedToolRegistry::get_tools_for_agent(AgentType::Perception);
    
    info!(
        "Tool registration complete - Orchestrator: {}, Strategic: {}, Tactical: {}, Perception: {} tools",
        orchestrator_tools.len(),
        strategic_tools.len(),
        tactical_tools.len(),
        perception_tools.len()
    );
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Note: Actual tests would require a full AppState setup
    // which is complex due to all the dependencies
    
    #[test]
    fn test_tool_initialization_compiles() {
        // This test just ensures the code compiles
        // Real testing would be done in integration tests
    }
}