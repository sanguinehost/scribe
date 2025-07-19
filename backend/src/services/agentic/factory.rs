//! Factory for creating and configuring the agentic narrative system.

use std::sync::Arc;
use tracing::info;

use crate::{
    llm::AiClient,
    services::{ChronicleService, LorebookService},
    state::AppState,
};

use super::{
    agent_runner::{NarrativeAgentRunner, NarrativeWorkflowConfig},
    narrative_tools::{
        CreateChronicleEventTool, CreateLorebookEntryTool,
        AnalyzeTextSignificanceTool, ExtractTemporalEventsTool, ExtractWorldConceptsTool,
        SearchKnowledgeBaseTool, UpdateLorebookEntryTool
    },
    entity_resolution_tool::EntityResolutionTool,
    tactical_agent::TacticalAgent,
    perception_agent::PerceptionAgent,
    strategic_agent::StrategicAgent,
    tools::{
        hierarchy_tools::{PromoteEntityHierarchyTool, GetEntityHierarchyTool},
        ai_powered_tools::{AnalyzeHierarchyRequestTool, SuggestHierarchyPromotionTool, UpdateSalienceTool},
    },
    registry::ToolRegistry,
};

/// Factory for creating a fully configured agentic narrative system
pub struct AgenticNarrativeFactory;

impl AgenticNarrativeFactory {
    /// Create a complete agentic narrative system with all tools registered
    pub fn create_system(
        ai_client: Arc<dyn AiClient>,
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        app_state: Arc<AppState>,
        config: Option<NarrativeWorkflowConfig>,
    ) -> NarrativeAgentRunner {
        info!("Creating agentic narrative system");

        // Create tool registry
        let mut registry = ToolRegistry::new();

        // Register core tools
        Self::register_core_tools(
            &mut registry,
            ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            app_state.clone(),
        );

        let registry = Arc::new(registry);
        let config = config.unwrap_or_default();

        info!(
            "Agentic system created with {} tools, using triage model: {}, planning model: {}",
            registry.list_tools().len(),
            config.triage_model,
            config.planning_model
        );

        NarrativeAgentRunner::new(app_state.clone(), registry, config, chronicle_service, app_state.token_counter.clone())
    }

    /// Create agentic narrative system with individual dependencies (no circular dependency)
    pub fn create_system_with_deps(
        ai_client: Arc<dyn AiClient>,
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        qdrant_service: Arc<dyn crate::vector_db::qdrant_client::QdrantClientServiceTrait + Send + Sync>,
        embedding_client: Arc<dyn crate::llm::EmbeddingClient + Send + Sync>,
        app_state: Arc<AppState>,
        config: Option<NarrativeWorkflowConfig>,
    ) -> NarrativeAgentRunner {
        info!("Creating agentic narrative system with individual dependencies");
        
        let config = config.unwrap_or_else(Self::create_production_config);
        
        // Create tool registry
        let mut registry = ToolRegistry::new();
        
        // Register tools with individual dependencies
        Self::register_core_tools_with_deps(
            &mut registry,
            ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            qdrant_service,
            embedding_client,
            app_state.clone(),
        );
        
        let registry = Arc::new(registry);
        
        info!(
            "Agentic system created with {} tools, using triage model: {}, planning model: {}",
            registry.list_tools().len(),
            config.triage_model,
            config.planning_model
        );
        
        NarrativeAgentRunner::new(app_state.clone(), registry, config, chronicle_service, app_state.token_counter.clone())
    }

    /// Register all core tools in the registry
    fn register_core_tools(
        registry: &mut ToolRegistry,
        ai_client: Arc<dyn AiClient>,
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        app_state: Arc<AppState>,
    ) {
        // Triage tool - for Step 1 of the workflow
        let significance_tool = Arc::new(AnalyzeTextSignificanceTool::new(app_state.clone()));
        registry.add_tool(significance_tool);

        // Extraction tools - for Step 3 (no DB operations)
        let extract_events_tool = Arc::new(ExtractTemporalEventsTool::new(app_state.clone()));
        registry.add_tool(extract_events_tool);

        let extract_concepts_tool = Arc::new(ExtractWorldConceptsTool::new(app_state.clone()));
        registry.add_tool(extract_concepts_tool);

        // Creation tools - atomic DB operations for Step 4
        let create_event_tool = Arc::new(CreateChronicleEventTool::new(
            chronicle_service.clone(),
            app_state.clone(),
        ));
        registry.add_tool(create_event_tool);

        let create_lorebook_tool = Arc::new(CreateLorebookEntryTool::new(
            lorebook_service.clone(),
            app_state.clone(),
        ));
        registry.add_tool(create_lorebook_tool);

        // Knowledge search tools - using existing embeddings infrastructure
        let search_tool = Arc::new(SearchKnowledgeBaseTool::new(
            app_state.clone(),
        ));
        registry.add_tool(search_tool);

        // Lorebook management tools
        let update_lorebook_tool = Arc::new(UpdateLorebookEntryTool::new(
            lorebook_service.clone(),
            app_state.clone(),
        ));
        registry.add_tool(update_lorebook_tool);

        // Entity resolution tool
        let entity_resolution_tool = Arc::new(EntityResolutionTool::new(app_state.clone()));
        registry.add_tool(entity_resolution_tool);

        // Hierarchy management tools for ECS
        let promote_hierarchy_tool = Arc::new(PromoteEntityHierarchyTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(promote_hierarchy_tool);

        let get_hierarchy_tool = Arc::new(GetEntityHierarchyTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(get_hierarchy_tool);

        // AI-powered foundational tools
        let analyze_hierarchy_tool = Arc::new(AnalyzeHierarchyRequestTool::new(app_state.clone()));
        registry.add_tool(analyze_hierarchy_tool);

        let suggest_promotion_tool = Arc::new(SuggestHierarchyPromotionTool::new(app_state.clone()));
        registry.add_tool(suggest_promotion_tool);

        let update_salience_tool = Arc::new(UpdateSalienceTool::new(app_state.clone()));
        registry.add_tool(update_salience_tool);

        // World interaction tools for entity management
        let find_entity_tool = Arc::new(super::tools::world_interaction_tools::FindEntityTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(find_entity_tool);

        let get_entity_details_tool = Arc::new(super::tools::world_interaction_tools::GetEntityDetailsTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(get_entity_details_tool);

        let create_entity_tool = Arc::new(super::tools::world_interaction_tools::CreateEntityTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(create_entity_tool);

        let update_entity_tool = Arc::new(super::tools::world_interaction_tools::UpdateEntityTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(update_entity_tool);

        // Spatial query tools for hierarchy traversal
        let get_contained_entities_tool = Arc::new(super::tools::world_interaction_tools::GetContainedEntitiesTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(get_contained_entities_tool);

        let get_spatial_context_tool = Arc::new(super::tools::world_interaction_tools::GetSpatialContextTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(get_spatial_context_tool);
        
        // Entity movement tool
        let move_entity_tool = Arc::new(super::tools::world_interaction_tools::MoveEntityTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(move_entity_tool);

        // Inventory management tools
        let add_item_to_inventory_tool = Arc::new(super::tools::world_interaction_tools::AddItemToInventoryTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(add_item_to_inventory_tool);

        let remove_item_from_inventory_tool = Arc::new(super::tools::world_interaction_tools::RemoveItemFromInventoryTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(remove_item_from_inventory_tool);

        // Relationship management tools
        let update_relationship_tool = Arc::new(super::tools::world_interaction_tools::UpdateRelationshipTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(update_relationship_tool);

        info!("Registered {} core tools", registry.list_tools().len());
    }

    /// Register core tools with individual dependencies (no AppState required)
    fn register_core_tools_with_deps(
        registry: &mut ToolRegistry,
        ai_client: Arc<dyn AiClient>,
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        qdrant_service: Arc<dyn crate::vector_db::qdrant_client::QdrantClientServiceTrait + Send + Sync>,
        embedding_client: Arc<dyn crate::llm::EmbeddingClient + Send + Sync>,
        app_state: Arc<AppState>,
    ) {
        // Triage tool - for Step 1 of the workflow
        let significance_tool = Arc::new(AnalyzeTextSignificanceTool::new(app_state.clone()));
        registry.add_tool(significance_tool);

        // Extraction tools - atomic operations for Step 2
        let temporal_tool = Arc::new(ExtractTemporalEventsTool::new(app_state.clone()));
        registry.add_tool(temporal_tool);

        let world_tool = Arc::new(ExtractWorldConceptsTool::new(app_state.clone()));
        registry.add_tool(world_tool);

        // Creation tools - atomic DB operations for Step 4
        let create_event_tool = Arc::new(CreateChronicleEventTool::new(
            chronicle_service.clone(),
            app_state.clone(),
        ));
        registry.add_tool(create_event_tool);

        let create_lorebook_tool = Arc::new(CreateLorebookEntryTool::new(
            lorebook_service.clone(),
            app_state.clone(),
        ));
        registry.add_tool(create_lorebook_tool);

        // Knowledge search tools - using existing embeddings infrastructure
        let search_tool = Arc::new(SearchKnowledgeBaseTool::new(
            app_state.clone(),
        ));
        registry.add_tool(search_tool);
        
        // Lorebook management tools
        let update_lorebook_tool = Arc::new(UpdateLorebookEntryTool::new(
            lorebook_service.clone(),
            app_state.clone(),
        ));
        registry.add_tool(update_lorebook_tool);

        // Entity resolution tool
        let entity_resolution_tool = Arc::new(EntityResolutionTool::new(app_state.clone()));
        registry.add_tool(entity_resolution_tool);

        // Hierarchy management tools for ECS
        let promote_hierarchy_tool = Arc::new(PromoteEntityHierarchyTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(promote_hierarchy_tool);

        let get_hierarchy_tool = Arc::new(GetEntityHierarchyTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(get_hierarchy_tool);

        // AI-powered foundational tools
        let analyze_hierarchy_tool = Arc::new(AnalyzeHierarchyRequestTool::new(app_state.clone()));
        registry.add_tool(analyze_hierarchy_tool);

        let suggest_promotion_tool = Arc::new(SuggestHierarchyPromotionTool::new(app_state.clone()));
        registry.add_tool(suggest_promotion_tool);

        let update_salience_tool = Arc::new(UpdateSalienceTool::new(app_state.clone()));
        registry.add_tool(update_salience_tool);

        // World interaction tools for entity management
        let find_entity_tool = Arc::new(super::tools::world_interaction_tools::FindEntityTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(find_entity_tool);

        let get_entity_details_tool = Arc::new(super::tools::world_interaction_tools::GetEntityDetailsTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(get_entity_details_tool);

        let create_entity_tool = Arc::new(super::tools::world_interaction_tools::CreateEntityTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(create_entity_tool);

        let update_entity_tool = Arc::new(super::tools::world_interaction_tools::UpdateEntityTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(update_entity_tool);

        // Spatial query tools for hierarchy traversal
        let get_contained_entities_tool = Arc::new(super::tools::world_interaction_tools::GetContainedEntitiesTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(get_contained_entities_tool);

        let get_spatial_context_tool = Arc::new(super::tools::world_interaction_tools::GetSpatialContextTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(get_spatial_context_tool);
        
        // Entity movement tool
        let move_entity_tool = Arc::new(super::tools::world_interaction_tools::MoveEntityTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(move_entity_tool);

        // Inventory management tools
        let add_item_to_inventory_tool = Arc::new(super::tools::world_interaction_tools::AddItemToInventoryTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(add_item_to_inventory_tool);

        let remove_item_from_inventory_tool = Arc::new(super::tools::world_interaction_tools::RemoveItemFromInventoryTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(remove_item_from_inventory_tool);

        // Relationship management tools
        let update_relationship_tool = Arc::new(super::tools::world_interaction_tools::UpdateRelationshipTool::new(app_state.ecs_entity_manager.clone()));
        registry.add_tool(update_relationship_tool);

        info!("Registered {} core tools", registry.list_tools().len());
    }

    /// Create a development/testing configuration
    pub fn create_dev_config() -> NarrativeWorkflowConfig {
        let config = crate::config::Config::default();
        NarrativeWorkflowConfig {
            triage_model: config.agentic_triage_model,
            planning_model: config.agentic_planning_model,
            max_tool_executions: 15, // Increased to allow multiple tool calls per batch
            enable_cost_optimizations: true,
        }
    }
    
    /// Create configuration from app config
    pub fn create_config_from_app_config(config: &crate::config::Config) -> NarrativeWorkflowConfig {
        NarrativeWorkflowConfig {
            triage_model: config.agentic_triage_model.clone(),
            planning_model: config.agentic_planning_model.clone(),
            max_tool_executions: config.agentic_max_tool_executions,
            enable_cost_optimizations: true,
        }
    }

    /// Create a production configuration
    pub fn create_production_config() -> NarrativeWorkflowConfig {
        let config = crate::config::Config::default();
        NarrativeWorkflowConfig {
            triage_model: config.agentic_triage_model,
            planning_model: config.agentic_planning_model,
            max_tool_executions: 5,
            enable_cost_optimizations: true,
        }
    }

    /// Create a TacticalAgent instance with proper dependencies
    /// 
    /// This factory method creates a TacticalAgent with all required dependencies
    /// instantiated from the provided AppState. This ensures proper service integration
    /// and dependency injection for the hierarchical agent framework.
    pub fn create_tactical_agent(app_state: &Arc<AppState>) -> Arc<TacticalAgent> {
        use crate::services::planning::{PlanningService, PlanValidatorService};
        
        info!("Creating TacticalAgent with dependencies");
        
        // Create PlanningService and PlanValidatorService dependencies
        let planning_service = Arc::new(PlanningService::new(
            app_state.ai_client.clone(),
            app_state.ecs_entity_manager.clone(),
            app_state.redis_client.clone(),
            Arc::new(app_state.pool.clone()),
            app_state.config.tactical_agent_model.clone(),
        ));
        
        let plan_validator = Arc::new(PlanValidatorService::new(
            app_state.ecs_entity_manager.clone(),
            app_state.redis_client.clone(),
        ));
        
        // Create TacticalAgent with all dependencies
        let tactical_agent = Arc::new(TacticalAgent::new(
            app_state.ai_client.clone(),
            app_state.ecs_entity_manager.clone(),
            planning_service,
            plan_validator,
            app_state.redis_client.clone(),
        ));
        
        info!("TacticalAgent created successfully");
        tactical_agent
    }
    
    /// Create a PerceptionAgent instance with proper dependencies
    /// 
    /// This factory method creates a PerceptionAgent with all required dependencies
    /// for asynchronous world state processing from AI responses.
    pub fn create_perception_agent(app_state: &Arc<AppState>) -> Arc<PerceptionAgent> {
        use crate::services::planning::{PlanningService, PlanValidatorService};
        
        info!("Creating PerceptionAgent with dependencies");
        
        // Create PlanningService and PlanValidatorService dependencies
        let planning_service = Arc::new(PlanningService::new(
            app_state.ai_client.clone(),
            app_state.ecs_entity_manager.clone(),
            app_state.redis_client.clone(),
            Arc::new(app_state.pool.clone()),
            app_state.config.tactical_agent_model.clone(),
        ));
        
        let plan_validator = Arc::new(PlanValidatorService::new(
            app_state.ecs_entity_manager.clone(),
            app_state.redis_client.clone(),
        ));
        
        // Create PerceptionAgent with all dependencies
        let perception_agent = Arc::new(PerceptionAgent::new(
            app_state.ai_client.clone(),
            app_state.ecs_entity_manager.clone(),
            planning_service,
            plan_validator,
            app_state.redis_client.clone(),
            app_state.clone(),
            app_state.config.perception_agent_model.clone(),
        ));
        
        info!("PerceptionAgent created successfully");
        perception_agent
    }

    /// Create a StrategicAgent instance with proper dependencies
    /// 
    /// This factory method creates a StrategicAgent with all required dependencies
    /// for high-level narrative direction and strategic planning.
    pub fn create_strategic_agent(app_state: &Arc<AppState>) -> Arc<StrategicAgent> {
        info!("Creating StrategicAgent with dependencies");
        
        // Create StrategicAgent with minimal dependencies (doesn't need planning services)
        let strategic_agent = Arc::new(StrategicAgent::new(
            app_state.ai_client.clone(),
            app_state.ecs_entity_manager.clone(),
            app_state.redis_client.clone(),
            app_state.config.strategic_agent_model.clone(),
        ));
        
        info!("StrategicAgent created successfully");
        strategic_agent
    }
}