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
    tool_registration::register_all_tools,
    tool_registry::ToolRegistry as DynamicToolRegistry,
    registry::ToolRegistry,
    tactical_agent::TacticalAgent,
    perception_agent::PerceptionAgent,
    strategic_agent::StrategicAgent,
};

/// Factory for creating a fully configured agentic narrative system
pub struct AgenticNarrativeFactory;

impl AgenticNarrativeFactory {
    /// Create a complete agentic narrative system with all tools registered
    pub fn create_system(
        _ai_client: Arc<dyn AiClient>, // Available through app_state
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        app_state: Arc<AppState>,
        config: Option<NarrativeWorkflowConfig>,
    ) -> NarrativeAgentRunner {
        info!("Creating agentic narrative system with dynamic tool registration");

        // Register all tools using the new dynamic system
        register_all_tools(
            app_state.clone(),
            chronicle_service.clone(),
            lorebook_service.clone(),
        ).expect("Failed to register tools");

        // Create a legacy registry adapter for compatibility
        let registry = Self::create_legacy_registry_adapter();
        let config = config.unwrap_or_default();

        let tool_count = DynamicToolRegistry::list_tool_names().len();
        info!(
            "Agentic system created with {} dynamically registered tools, using triage model: {}, planning model: {}",
            tool_count,
            config.triage_model,
            config.planning_model
        );

        // Log available tool categories
        let categories = [
            super::tool_registry::ToolCategory::Extraction,
            super::tool_registry::ToolCategory::Creation,
            super::tool_registry::ToolCategory::Search,
            super::tool_registry::ToolCategory::EntityManagement,
            super::tool_registry::ToolCategory::Hierarchy,
            super::tool_registry::ToolCategory::AIAnalysis,
            super::tool_registry::ToolCategory::WorldState,
            super::tool_registry::ToolCategory::Narrative,
        ];
        
        for category in &categories {
            let tools = DynamicToolRegistry::get_tools_by_category(category.clone());
            if !tools.is_empty() {
                info!("  {:?} tools: {}", category, tools.join(", "));
            }
        }

        NarrativeAgentRunner::new(app_state.clone(), registry, config, chronicle_service, app_state.token_counter.clone())
    }

    /// Create agentic narrative system with individual dependencies (no circular dependency)
    pub fn create_system_with_deps(
        _ai_client: Arc<dyn AiClient>, // Available through app_state
        chronicle_service: Arc<ChronicleService>,
        lorebook_service: Arc<LorebookService>,
        _qdrant_service: Arc<dyn crate::vector_db::qdrant_client::QdrantClientServiceTrait + Send + Sync>, // Available through app_state
        _embedding_client: Arc<dyn crate::llm::EmbeddingClient + Send + Sync>, // Available through app_state
        app_state: Arc<AppState>,
        config: Option<NarrativeWorkflowConfig>,
    ) -> NarrativeAgentRunner {
        info!("Creating agentic narrative system with individual dependencies and dynamic tool registration");
        
        let config = config.unwrap_or_else(Self::create_production_config);
        
        // Register all tools using the new dynamic system
        register_all_tools(
            app_state.clone(),
            chronicle_service.clone(),
            lorebook_service.clone(),
        ).expect("Failed to register tools");
        
        // Create a legacy registry adapter for compatibility
        let registry = Self::create_legacy_registry_adapter();
        
        let tool_count = DynamicToolRegistry::list_tool_names().len();
        info!(
            "Agentic system created with {} dynamically registered tools, using triage model: {}, planning model: {}",
            tool_count,
            config.triage_model,
            config.planning_model
        );
        
        NarrativeAgentRunner::new(app_state.clone(), registry, config, chronicle_service, app_state.token_counter.clone())
    }
    
    /// Create a legacy registry adapter that bridges the new dynamic registry with the old system
    fn create_legacy_registry_adapter() -> Arc<ToolRegistry> {
        let mut legacy_registry = ToolRegistry::new();
        
        // Get all registered tools from the dynamic registry
        for tool_name in DynamicToolRegistry::list_tool_names() {
            if let Ok(tool) = DynamicToolRegistry::get_tool(&tool_name) {
                legacy_registry.add_tool(tool);
            }
        }
        
        Arc::new(legacy_registry)
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