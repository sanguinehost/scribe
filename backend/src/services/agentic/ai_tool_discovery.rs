//! AI-Powered Tool Discovery Service
//! 
//! This module provides intelligent tool discovery and recommendation
//! for agents based on their current task and context.

use std::sync::Arc;
use serde::{Serialize, Deserialize};
use serde_json::{json, Value as JsonValue};
use tracing::info;

use crate::{
    errors::AppError,
    llm::AiClient,
    services::agentic::unified_tool_registry::{
        UnifiedToolRegistry, AgentType, ToolMetadata, ToolRecommendation,
        ToolCategory,
    },
};
use genai::chat::{ChatMessage, ChatRequest, ChatOptions};

/// AI-powered tool discovery service
pub struct AiToolDiscoveryService {
    ai_client: Arc<dyn AiClient>,
}

impl AiToolDiscoveryService {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self { ai_client }
    }
    
    /// Discover tools for a specific task using AI
    pub async fn discover_tools_for_task(
        &self,
        agent: AgentType,
        task_description: &str,
        current_context: &TaskContext,
    ) -> Result<DiscoveryResult, AppError> {
        // Get all tools available to this agent
        let available_tools = UnifiedToolRegistry::get_tools_for_agent(agent);
        
        if available_tools.is_empty() {
            return Ok(DiscoveryResult {
                recommendations: vec![],
                reasoning: "No tools available for this agent type".to_string(),
                suggested_sequence: None,
            });
        }
        
        // Build AI prompt for tool discovery
        let discovery_prompt = self.build_discovery_prompt(
            agent,
            task_description,
            current_context,
            &available_tools,
        );
        
        // Create a combined prompt for the AI
        let combined_prompt = format!(
            "{}\n\nTask: {}\nContext: {:?}\n\nRecommend the best tools for this task. Respond with a JSON object containing 'recommendations' (array of objects with tool_name, relevance_score, reasoning, order), 'overall_reasoning', and optional 'suggested_sequence' and 'warnings'.",
            discovery_prompt, task_description, current_context
        );
        
        // Create a simple chat request
        let discovery_request = ChatRequest::from_user(combined_prompt);
        
        // Set up chat options with temperature
        let chat_options = Some(ChatOptions {
            temperature: Some(0.3),
            ..Default::default()
        });
        
        // Get AI recommendations
        let response = self.ai_client.exec_chat(
            "gemini-2.5-flash", // Use a fast model for discovery
            discovery_request,
            chat_options,
        ).await?;
        
        // Parse the response - the content is in the ChatResponse structure
        let content_text = response.first_content_text_as_str()
            .ok_or_else(|| AppError::AiServiceError("Empty response from AI".to_string()))?;
            
        let ai_result: AiDiscoveryResponse = serde_json::from_str(content_text)
            .map_err(|e| AppError::AiServiceError(format!("Failed to parse AI response: {}", e)))?;
        
        // Convert to tool recommendations
        let mut recommendations = Vec::new();
        for ai_rec in ai_result.recommendations {
            // Find the tool metadata
            if let Some(tool_meta) = available_tools.iter()
                .find(|t| t.name == ai_rec.tool_name) {
                
                // Get the first relevant example
                let example = tool_meta.usage_examples.first().cloned();
                
                recommendations.push(ToolRecommendation {
                    tool_name: ai_rec.tool_name,
                    relevance_score: ai_rec.relevance_score,
                    reasoning: ai_rec.reasoning,
                    usage_example: example,
                });
            }
        }
        
        // Sort by relevance score
        recommendations.sort_by(|a, b| {
            b.relevance_score.partial_cmp(&a.relevance_score).unwrap()
        });
        
        Ok(DiscoveryResult {
            recommendations,
            reasoning: ai_result.overall_reasoning,
            suggested_sequence: ai_result.suggested_sequence,
        })
    }
    
    /// Build a comprehensive prompt for tool discovery
    fn build_discovery_prompt(
        &self,
        agent: AgentType,
        task_description: &str,
        context: &TaskContext,
        available_tools: &[ToolMetadata],
    ) -> String {
        let agent_role = match agent {
            AgentType::Orchestrator => "the Orchestrator coordinating all agents",
            AgentType::Strategic => "the Strategic Agent focused on high-level planning",
            AgentType::Tactical => "the Tactical Agent focused on execution planning",
            AgentType::Perception => "the Perception Agent observing world state",
            AgentType::Custom(_) => "a custom agent",
        };
        
        let mut prompt = format!(
            "You are an AI assistant helping {} select the best tools for a task.\n\n",
            agent_role
        );
        
        prompt.push_str("AVAILABLE TOOLS:\n\n");
        
        // Group tools by category for better organization
        let mut by_category: std::collections::HashMap<ToolCategory, Vec<&ToolMetadata>> = 
            std::collections::HashMap::new();
        
        for tool in available_tools {
            by_category.entry(tool.category).or_default().push(tool);
        }
        
        for (category, tools) in by_category {
            prompt.push_str(&format!("\n{:?} Tools:\n", category));
            
            for tool in tools {
                prompt.push_str(&format!(
                    "\n- {} (v{})\n  Description: {}\n  When to use: {}\n  When NOT to use: {}\n  Capabilities: {}\n  Tags: {}\n",
                    tool.name,
                    tool.version,
                    tool.description,
                    tool.when_to_use,
                    tool.when_not_to_use,
                    tool.capabilities.iter()
                        .map(|c| format!("{} {}", c.action, c.target))
                        .collect::<Vec<_>>()
                        .join(", "),
                    tool.tags.join(", ")
                ));
            }
        }
        
        prompt.push_str("\n\nTOOL SELECTION CRITERIA:\n");
        prompt.push_str("1. Match tool capabilities to the task requirements\n");
        prompt.push_str("2. Consider the agent's role and responsibilities\n");
        prompt.push_str("3. Respect tool dependencies and execution order\n");
        prompt.push_str("4. Prioritize tools that work well together\n");
        prompt.push_str("5. Consider resource requirements and performance\n");
        prompt.push_str("6. Follow security policies and access restrictions\n");
        
        prompt.push_str("\n\nCURRENT CONTEXT:\n");
        prompt.push_str(&format!("- Phase: {:?}\n", context.workflow_phase));
        prompt.push_str(&format!("- Previous tools used: {:?}\n", context.previous_tools));
        prompt.push_str(&format!("- Active entities: {}\n", context.active_entities.len()));
        
        prompt.push_str("\n\nYour response must include:\n");
        prompt.push_str("1. Recommended tools with relevance scores (0-1)\n");
        prompt.push_str("2. Clear reasoning for each recommendation\n");
        prompt.push_str("3. Suggested execution order if multiple tools are needed\n");
        prompt.push_str("4. Any warnings about tool limitations or conflicts\n");
        
        prompt
    }
    
    /// Learn from tool usage patterns
    pub async fn learn_from_execution(
        &self,
        agent: AgentType,
        tool_name: &str,
        task_description: &str,
        success: bool,
        execution_time_ms: u64,
    ) -> Result<(), AppError> {
        // TODO: Implement learning system that:
        // 1. Tracks successful tool combinations
        // 2. Identifies common patterns
        // 3. Improves future recommendations
        // 4. Adapts to agent preferences
        
        info!(
            "Learning from execution: agent={:?}, tool={}, success={}, time={}ms",
            agent, tool_name, success, execution_time_ms
        );
        
        Ok(())
    }
}

/// Task context for tool discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskContext {
    /// Current workflow phase
    pub workflow_phase: WorkflowPhase,
    /// Tools already used in this workflow
    pub previous_tools: Vec<String>,
    /// Currently active entities
    pub active_entities: Vec<String>,
    /// Recent events or changes
    pub recent_events: Vec<String>,
    /// Additional context data
    pub metadata: JsonValue,
}

/// Workflow phases for context
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowPhase {
    /// Initial perception and understanding
    Perception,
    /// Strategic planning
    Strategy,
    /// Tactical execution planning
    Tactics,
    /// Execution of actions
    Execution,
    /// Reflection and learning
    Reflection,
}

/// Result of AI tool discovery
#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryResult {
    /// Recommended tools sorted by relevance
    pub recommendations: Vec<ToolRecommendation>,
    /// Overall reasoning for recommendations
    pub reasoning: String,
    /// Suggested execution sequence
    pub suggested_sequence: Option<Vec<String>>,
}

/// Internal AI response structure
#[derive(Debug, Deserialize)]
struct AiDiscoveryResponse {
    recommendations: Vec<AiToolRecommendation>,
    overall_reasoning: String,
    suggested_sequence: Option<Vec<String>>,
    warnings: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct AiToolRecommendation {
    tool_name: String,
    relevance_score: f64,
    reasoning: String,
    order: u32,
}

/// Service for agent-specific tool discovery
pub struct AgentToolDiscovery {
    discovery_service: Arc<AiToolDiscoveryService>,
}

impl AgentToolDiscovery {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self {
            discovery_service: Arc::new(AiToolDiscoveryService::new(ai_client)),
        }
    }
    
    /// Get tool recommendations for the Orchestrator
    pub async fn discover_for_orchestrator(
        &self,
        phase: WorkflowPhase,
        task: &str,
        context: &TaskContext,
    ) -> Result<Vec<ToolRecommendation>, AppError> {
        // Orchestrator has special logic for coordinating other agents
        let mut enhanced_context = context.clone();
        enhanced_context.metadata["orchestrator_phase"] = json!(phase);
        
        let result = self.discovery_service
            .discover_tools_for_task(
                AgentType::Orchestrator,
                task,
                &enhanced_context,
            )
            .await?;
        
        // Filter based on orchestrator's current phase
        let filtered = match phase {
            WorkflowPhase::Perception => {
                result.recommendations.into_iter()
                    .filter(|r| {
                        // Prioritize perception and analysis tools
                        r.tool_name.contains("analyze") || 
                        r.tool_name.contains("query") ||
                        r.tool_name.contains("get")
                    })
                    .collect()
            },
            WorkflowPhase::Strategy => {
                result.recommendations.into_iter()
                    .filter(|r| {
                        // Prioritize planning and assessment tools
                        r.tool_name.contains("assess") || 
                        r.tool_name.contains("suggest") ||
                        r.tool_name.contains("analyze")
                    })
                    .collect()
            },
            WorkflowPhase::Tactics => {
                result.recommendations.into_iter()
                    .filter(|r| {
                        // Prioritize execution planning tools
                        r.tool_name.contains("create") || 
                        r.tool_name.contains("update") ||
                        r.tool_name.contains("manage")
                    })
                    .collect()
            },
            _ => result.recommendations,
        };
        
        Ok(filtered)
    }
    
    /// Get tools that should always be available to an agent
    pub fn get_core_tools_for_agent(agent: AgentType) -> Vec<&'static str> {
        match agent {
            AgentType::Orchestrator => vec![
                "analyze_text_significance",
                "search_knowledge_base",
                "get_entity_hierarchy",
            ],
            AgentType::Strategic => vec![
                "assess_narrative_opportunities",
                "suggest_hierarchy_promotion",
                "search_knowledge_base",
            ],
            AgentType::Tactical => vec![
                "create_entity",
                "update_entity",
                "move_entity",
                "manage_inventory",
            ],
            AgentType::Perception => vec![
                "get_visible_entities_and_exits",
                "get_spatial_context",
                "query_inventory",
            ],
            AgentType::Custom(_) => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_workflow_phase_filtering() {
        let phase = WorkflowPhase::Perception;
        assert_eq!(phase, WorkflowPhase::Perception);
    }
    
    #[test]
    fn test_core_tools_for_orchestrator() {
        let tools = AgentToolDiscovery::get_core_tools_for_agent(AgentType::Orchestrator);
        assert!(tools.contains(&"analyze_text_significance"));
        assert!(tools.contains(&"search_knowledge_base"));
    }
}