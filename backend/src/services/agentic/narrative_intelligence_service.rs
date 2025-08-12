//! Defines the `NarrativeIntelligenceService` which is the main entry point
//! for the agentic narrative layer.

use std::sync::Arc;

use super::{
    executor::ToolExecutor, orchestrator::WorkflowOrchestrator, registry::ToolRegistry,
    narrative_tools::SearchKnowledgeBaseTool,
};
use crate::llm::AiClient;
use crate::vector_db::VectorDb;

/// The `NarrativeIntelligenceService` is responsible for initializing and
/// providing access to the agentic workflow components.
pub struct NarrativeIntelligenceService {
    orchestrator: Arc<WorkflowOrchestrator>,
}

impl NarrativeIntelligenceService {
    /// Creates a new `NarrativeIntelligenceService`.
    ///
    /// This method initializes the `ToolRegistry`, populates it with the
    /// available tools, and sets up the `ToolExecutor` and `WorkflowOrchestrator`.
    pub fn new(
        triage_client: Arc<dyn AiClient>,
        planning_client: Arc<dyn AiClient>,
        _qdrant_service: Arc<dyn VectorDb>,
    ) -> Self {
        // 1. Create and populate the ToolRegistry
        let mut registry = ToolRegistry::new();
        // NOTE: SearchKnowledgeBaseTool now requires AppState which isn't available here
        // This appears to be an older implementation. The actual tool registration
        // happens in factory.rs which has proper dependencies.
        // let search_tool = Arc::new(SearchKnowledgeBaseTool::new(qdrant_service));
        // registry.add_tool(search_tool);
        // ... add other tools here in the future

        let registry = Arc::new(registry);

        // 2. Create the ToolExecutor
        let tool_executor = Arc::new(ToolExecutor::new(registry.clone()));

        // 3. Create the WorkflowOrchestrator
        let orchestrator = Arc::new(WorkflowOrchestrator::new(
            triage_client,
            planning_client,
            tool_executor,
        ));

        Self { orchestrator }
    }

    /// Returns a reference to the `WorkflowOrchestrator`.
    pub fn orchestrator(&self) -> &Arc<WorkflowOrchestrator> {
        &self.orchestrator
    }
}