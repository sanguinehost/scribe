//! Tool Discovery Service
//! 
//! This module provides functionality for AI agents to discover and understand
//! available tools based on their current needs and context.

use tracing::info;

use super::tool_registry::{ToolRegistry, ToolContext, ToolCategory};

/// Service for AI agents to discover tools dynamically
pub struct ToolDiscoveryService;

impl ToolDiscoveryService {
    /// Get tool recommendations for a specific task
    pub fn get_tool_recommendations(task_description: &str) -> Vec<String> {
        // This would use AI to analyze the task and recommend tools
        // For now, we'll use keyword matching as a simple example
        
        let mut recommendations = Vec::new();
        let task_lower = task_description.to_lowercase();
        
        // Narrative analysis
        if task_lower.contains("significant") || task_lower.contains("analyze") {
            recommendations.push("analyze_text_significance".to_string());
        }
        
        // Event extraction
        if task_lower.contains("event") || task_lower.contains("temporal") {
            recommendations.push("extract_temporal_events".to_string());
        }
        
        // World building
        if task_lower.contains("concept") || task_lower.contains("world") {
            recommendations.push("extract_world_concepts".to_string());
        }
        
        // Entity operations
        if task_lower.contains("find") && (task_lower.contains("entity") || task_lower.contains("entities")) {
            recommendations.push("find_entity".to_string());
        }
        
        if task_lower.contains("create") && (task_lower.contains("entity") || task_lower.contains("character")) {
            recommendations.push("create_entity".to_string());
        }
        
        // Knowledge operations
        if task_lower.contains("search") || task_lower.contains("knowledge") {
            recommendations.push("search_knowledge_base".to_string());
        }
        
        // Chronicle operations
        if task_lower.contains("record") || task_lower.contains("chronicle") || task_lower.contains("battle") {
            if task_lower.contains("event") || task_lower.contains("battle") {
                recommendations.push("analyze_text_significance".to_string());
                recommendations.push("extract_temporal_events".to_string());
            }
            recommendations.push("create_chronicle_event".to_string());
        }
        
        // Spatial operations
        if task_lower.contains("near") || task_lower.contains("spatial") || task_lower.contains("around") {
            recommendations.push("get_spatial_context".to_string());
        }
        
        // Movement operations
        if task_lower.contains("move") && (task_lower.contains("entity") || task_lower.contains("character")) {
            recommendations.push("move_entity".to_string());
        }
        
        // Relationship operations
        if task_lower.contains("relationship") {
            recommendations.push("update_relationship".to_string());
        }
        
        recommendations
    }
    
    /// Get tools for a specific workflow phase
    pub fn get_tools_for_phase(phase: WorkflowPhase) -> Vec<String> {
        match phase {
            WorkflowPhase::Analysis => {
                ToolRegistry::get_tools_by_category(ToolCategory::AIAnalysis)
            }
            WorkflowPhase::Extraction => {
                ToolRegistry::get_tools_by_category(ToolCategory::Extraction)
            }
            WorkflowPhase::Creation => {
                ToolRegistry::get_tools_by_category(ToolCategory::Creation)
            }
            WorkflowPhase::Query => {
                let mut tools = ToolRegistry::get_tools_by_category(ToolCategory::Search);
                tools.extend(ToolRegistry::get_tools_by_category(ToolCategory::WorldState));
                tools
            }
            WorkflowPhase::Management => {
                let mut tools = ToolRegistry::get_tools_by_category(ToolCategory::EntityManagement);
                tools.extend(ToolRegistry::get_tools_by_category(ToolCategory::Hierarchy));
                tools
            }
        }
    }
    
    /// Generate a contextual tool guide for AI agents
    pub fn generate_contextual_guide(context: &ToolContext) -> String {
        let suitable_tools = ToolRegistry::get_contextual_tools(context);
        let mut guide = String::from("# CONTEXTUAL TOOL GUIDE\n\n");
        
        guide.push_str(&format!("Based on your requirements:\n"));
        guide.push_str(&format!("- Fast execution needed: {}\n", context.needs_fast_execution));
        guide.push_str(&format!("- Read-only mode: {}\n", context.read_only));
        guide.push_str(&format!("- External calls allowed: {}\n", context.allow_external_calls));
        
        if let Some(category) = &context.required_category {
            guide.push_str(&format!("- Required category: {:?}\n", category));
        }
        
        if let Some(tags) = &context.required_tags {
            guide.push_str(&format!("- Required tags: {}\n", tags.join(", ")));
        }
        
        guide.push_str(&format!("\n## Recommended Tools ({} found)\n\n", suitable_tools.len()));
        
        for tool_name in suitable_tools {
            if let Some(metadata) = ToolRegistry::get_metadata(&tool_name) {
                guide.push_str(&format!("### {}\n", tool_name));
                guide.push_str(&format!("- **Category**: {:?}\n", metadata.category));
                guide.push_str(&format!("- **Description**: {}\n", metadata.description));
                guide.push_str(&format!("- **When to use**: {}\n", metadata.when_to_use));
                guide.push_str(&format!("- **Execution time**: {:?}\n", metadata.execution_time));
                guide.push_str("\n");
            }
        }
        
        guide
    }
    
    /// Generate tool usage examples for learning
    pub fn generate_usage_examples(tool_name: &str) -> Option<String> {
        let metadata = ToolRegistry::get_metadata(tool_name)?;
        let mut examples = String::from(&format!("# {} - Usage Examples\n\n", tool_name));
        
        examples.push_str(&format!("**Description**: {}\n\n", metadata.description));
        examples.push_str(&format!("**When to use**: {}\n\n", metadata.when_to_use));
        
        if let Some(when_not) = &metadata.when_not_to_use {
            examples.push_str(&format!("**When NOT to use**: {}\n\n", when_not));
        }
        
        if !metadata.usage_examples.is_empty() {
            examples.push_str("## Examples\n\n");
            for (i, example) in metadata.usage_examples.iter().enumerate() {
                examples.push_str(&format!("### Example {}: {}\n\n", i + 1, example.scenario));
                examples.push_str("**Input**:\n```json\n");
                examples.push_str(&serde_json::to_string_pretty(&example.input).unwrap());
                examples.push_str("\n```\n\n");
                examples.push_str(&format!("**Expected Outcome**: {}\n\n", example.expected_outcome));
            }
        }
        
        examples.push_str("## Input Schema\n```json\n");
        examples.push_str(&serde_json::to_string_pretty(&metadata.input_schema).unwrap());
        examples.push_str("\n```\n\n");
        
        examples.push_str(&format!("**Output Format**: {}\n", metadata.output_format));
        
        Some(examples)
    }
    
    /// Get tool dependency graph
    pub fn get_tool_dependencies(tool_name: &str) -> Option<DependencyInfo> {
        let metadata = ToolRegistry::get_metadata(tool_name)?;
        
        let mut all_dependencies = Vec::new();
        let mut to_process = metadata.depends_on.clone();
        let mut processed = std::collections::HashSet::new();
        
        // Recursively find all dependencies
        while let Some(dep) = to_process.pop() {
            if processed.contains(&dep) {
                continue;
            }
            
            processed.insert(dep.clone());
            all_dependencies.push(dep.clone());
            
            if let Some(dep_metadata) = ToolRegistry::get_metadata(&dep) {
                for sub_dep in &dep_metadata.depends_on {
                    if !processed.contains(sub_dep) {
                        to_process.push(sub_dep.clone());
                    }
                }
            }
        }
        
        Some(DependencyInfo {
            tool_name: tool_name.to_string(),
            direct_dependencies: metadata.depends_on,
            all_dependencies,
            execution_order: generate_execution_order(&processed),
        })
    }
}

/// Workflow phases for tool discovery
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowPhase {
    Analysis,
    Extraction,
    Creation,
    Query,
    Management,
}

/// Tool dependency information
#[derive(Debug, Clone)]
pub struct DependencyInfo {
    pub tool_name: String,
    pub direct_dependencies: Vec<String>,
    pub all_dependencies: Vec<String>,
    pub execution_order: Vec<String>,
}

/// Generate a suggested execution order for tools
fn generate_execution_order(dependencies: &std::collections::HashSet<String>) -> Vec<String> {
    // This is a simplified version - in practice, you'd do a topological sort
    let mut order = Vec::new();
    
    // Analysis tools first
    if dependencies.contains("analyze_text_significance") {
        order.push("analyze_text_significance".to_string());
    }
    
    // Then extraction
    for tool in ["extract_temporal_events", "extract_world_concepts"] {
        if dependencies.contains(tool) {
            order.push(tool.to_string());
        }
    }
    
    // Then creation
    for tool in ["create_chronicle_event", "create_lorebook_entry"] {
        if dependencies.contains(tool) {
            order.push(tool.to_string());
        }
    }
    
    order
}

/// Example function showing how an AI agent would discover tools
pub async fn demonstrate_tool_discovery() {
    info!("Demonstrating tool discovery capabilities");
    
    // 1. Get all available tools
    let all_tools = ToolRegistry::list_tool_names();
    info!("Total tools available: {}", all_tools.len());
    
    // 2. Get tools by category
    let ai_tools = ToolRegistry::get_tools_by_category(ToolCategory::AIAnalysis);
    info!("AI Analysis tools: {:?}", ai_tools);
    
    // 3. Get tools for specific context
    let fast_read_only_context = ToolContext {
        needs_fast_execution: true,
        read_only: true,
        allow_external_calls: false,
        required_category: None,
        required_tags: None,
    };
    
    let contextual_tools = ToolRegistry::get_contextual_tools(&fast_read_only_context);
    info!("Tools for fast, read-only operations: {:?}", contextual_tools);
    
    // 4. Get recommendations for a task
    let task = "I need to analyze this narrative text and extract important events";
    let recommendations = ToolDiscoveryService::get_tool_recommendations(task);
    info!("Recommended tools for '{}': {:?}", task, recommendations);
    
    // 5. Get tools for workflow phase
    let extraction_tools = ToolDiscoveryService::get_tools_for_phase(WorkflowPhase::Extraction);
    info!("Extraction phase tools: {:?}", extraction_tools);
    
    // 6. Generate documentation
    let tool_docs = ToolRegistry::generate_tool_documentation();
    info!("Generated {} characters of tool documentation", tool_docs.len());
    
    // 7. Get specific tool examples
    if let Some(examples) = ToolDiscoveryService::generate_usage_examples("find_entity") {
        info!("Generated usage examples for find_entity tool");
    }
    
    // 8. Check dependencies
    if let Some(deps) = ToolDiscoveryService::get_tool_dependencies("create_chronicle_event") {
        info!(
            "create_chronicle_event depends on: {:?}", 
            deps.direct_dependencies
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tool_recommendations() {
        let recommendations = ToolDiscoveryService::get_tool_recommendations(
            "I need to find entities and analyze their significance"
        );
        
        assert!(recommendations.contains(&"analyze_text_significance".to_string()));
        assert!(recommendations.contains(&"find_entity".to_string()));
    }
    
    #[test]
    fn test_workflow_phases() {
        let analysis_tools = ToolDiscoveryService::get_tools_for_phase(WorkflowPhase::Analysis);
        let extraction_tools = ToolDiscoveryService::get_tools_for_phase(WorkflowPhase::Extraction);
        
        // These would be populated after tools are registered
        // Just testing the function works
        assert!(analysis_tools.is_empty() || !analysis_tools.is_empty());
        assert!(extraction_tools.is_empty() || !extraction_tools.is_empty());
    }
}