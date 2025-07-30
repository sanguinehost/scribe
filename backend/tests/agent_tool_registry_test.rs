//! Test that agents can properly use the dynamic tool registry

use scribe_backend::{
    services::agentic::{
        factory::AgenticNarrativeFactory,
        unified_tool_registry::{UnifiedToolRegistry, AgentType},
    },
    test_helpers::spawn_app,
};
use tracing::info;

#[tokio::test]
async fn test_agents_use_dynamic_tool_registry() {
    let test_app = spawn_app(false, false, false).await;
    
    // Create unified tool registry
    let registry = UnifiedToolRegistry::new();
    
    // Verify tools are registered for each agent type
    for agent_type in [AgentType::Orchestrator, AgentType::Strategic, AgentType::Tactical, AgentType::Perception] {
        let tools = registry.get_tools_for_agent(&agent_type);
        info!("Tools registered for {:?}: {}", agent_type, tools.len());
        assert!(!tools.is_empty(), "No tools registered for {:?}", agent_type);
    }
    
    // Create agents using factory (this should use the unified registry internally)
    let factory = AgenticNarrativeFactory::new(
        test_app.app_state.ai_client.clone(),
        test_app.app_state.ecs_entity_manager.clone(),
        test_app.app_state.planning_service.clone(),
        test_app.app_state.plan_validator.clone(),
        test_app.app_state.config.clone(),
        test_app.app_state.redis_client.clone(),
        test_app.app_state.pool.clone(),
        test_app.app_state.lorebook_service.clone(),
        test_app.app_state.shared_agent_context.clone(),
    );
    
    // Create each agent type
    let orchestrator = factory.create_orchestrator();
    let strategic = factory.create_strategic_agent();
    let tactical = factory.create_tactical_agent();
    let perception = factory.create_perception_agent();
    
    // Verify agents were created successfully
    assert!(orchestrator.is_ok(), "Failed to create orchestrator");
    assert!(strategic.is_ok(), "Failed to create strategic agent");
    assert!(tactical.is_ok(), "Failed to create tactical agent");
    assert!(perception.is_ok(), "Failed to create perception agent");
    
    info!("All agents created successfully with access to unified tool registry");
}