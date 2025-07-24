//! Example of a self-registering tool implementation
//! 
//! This shows how existing tools will be migrated to the new pattern

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use std::sync::Arc;

use crate::{
    errors::AppError,
    services::agentic::{
        tools::{ScribeTool, ToolError, ToolParams, ToolResult},
        unified_tool_registry::{
            SelfRegisteringTool, ToolCategory, ToolCapability, ToolExample,
            ToolSecurityPolicy, AgentType, DataAccessPolicy, AuditLevel,
            ResourceRequirements, ExecutionTime, ErrorCode,
        },
    },
    auth::session_dek::SessionDek,
};

/// Example: Migrated AnalyzeTextSignificanceTool
pub struct AnalyzeTextSignificanceTool {
    ai_client: Arc<dyn crate::llm::AiClient>,
}

impl AnalyzeTextSignificanceTool {
    pub fn new(ai_client: Arc<dyn crate::llm::AiClient>) -> Self {
        Self { ai_client }
    }
}

// First implement the base ScribeTool trait (existing)
#[async_trait]
impl ScribeTool for AnalyzeTextSignificanceTool {
    fn name(&self) -> &'static str {
        "analyze_text_significance"
    }
    
    fn description(&self) -> &'static str {
        "Analyzes narrative text to determine if it contains significant events, \
         world-building elements, or character development worthy of recording"
    }
    
    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The narrative text to analyze"
                },
                "context": {
                    "type": "string",
                    "description": "Additional context about the narrative"
                }
            },
            "required": ["text"]
        })
    }
    
    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        // Implementation would go here
        Ok(json!({
            "significance_score": 0.8,
            "is_significant": true,
            "category": "character_development",
            "reasoning": "Major character growth moment",
            "key_elements": ["emotional breakthrough", "relationship change"]
        }))
    }
}

// Now implement the new SelfRegisteringTool trait
#[async_trait]
impl SelfRegisteringTool for AnalyzeTextSignificanceTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "analyze".to_string(),
                target: "narrative text".to_string(),
                context: Some("for significance".to_string()),
            },
            ToolCapability {
                action: "identify".to_string(),
                target: "key events".to_string(),
                context: Some("in narrative".to_string()),
            },
            ToolCapability {
                action: "evaluate".to_string(),
                target: "character development".to_string(),
                context: None,
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you receive narrative text from the user and need to determine \
         if it contains events, character development, or world-building elements \
         that should be preserved in chronicles or lorebooks. This is typically \
         the first step in the narrative processing pipeline.".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for simple chat messages, queries, or commands that don't \
         contain narrative content. Also avoid using for text that has already \
         been analyzed or for non-narrative technical discussions.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "User describes a dramatic battle".to_string(),
                input: json!({
                    "text": "The Northern Fleet launched a surprise attack on the Crystal Spire at dawn, shattering the century-old peace treaty.",
                    "context": "Military conflict in fantasy world"
                }),
                expected_output: "High significance (0.9) with category 'world_event', identifying key elements like conflict initiation, treaty breaking, and location significance".to_string(),
            },
            ToolExample {
                scenario: "Character has emotional breakthrough".to_string(),
                input: json!({
                    "text": "Alice finally forgave her father, tears streaming down her face as they embraced for the first time in years.",
                    "context": "Character reconciliation scene"
                }),
                expected_output: "High significance (0.85) with category 'character_development', highlighting emotional growth and relationship healing".to_string(),
            },
        ]
    }
    
    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Perception,
                AgentType::Strategic,
            ],
            required_capabilities: vec![],
            rate_limit: None, // No rate limiting for analysis
            data_access: DataAccessPolicy {
                user_data: true, // Needs to read user narratives
                system_data: false,
                write_access: false, // Read-only tool
                allowed_scopes: vec!["narratives".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 50,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Uses AI client
            compute_intensive: false,
        }
    }
    
    fn dependencies(&self) -> Vec<String> {
        vec![] // No dependencies on other tools
    }
    
    fn tags(&self) -> Vec<String> {
        vec![
            "narrative".to_string(),
            "analysis".to_string(),
            "significance".to_string(),
            "triage".to_string(),
            "ai-powered".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "significance_score": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "description": "How significant the text is (0-1)"
                },
                "is_significant": {
                    "type": "boolean",
                    "description": "Whether the text meets significance threshold"
                },
                "category": {
                    "type": "string",
                    "enum": ["character_development", "world_event", "plot_advancement", "world_building", "dialogue", "other"],
                    "description": "Primary category of significance"
                },
                "reasoning": {
                    "type": "string",
                    "description": "Explanation of significance assessment"
                },
                "key_elements": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Key narrative elements identified"
                }
            },
            "required": ["significance_score", "is_significant", "category", "reasoning"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "EMPTY_TEXT".to_string(),
                description: "The provided text is empty or whitespace only".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "AI_SERVICE_ERROR".to_string(),
                description: "The AI service failed to analyze the text".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "INVALID_CONTEXT".to_string(),
                description: "The provided context is malformed".to_string(),
                retry_able: false,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "2.0.0" // Version 2 with self-registration
    }
}

// Self-registration happens at module initialization
pub fn register() -> Result<(), AppError> {
    // Commented out until we have proper tool registration working
    // use crate::register_tool;
    // register_tool!(AnalyzeTextSignificanceTool)
    Ok(())
}

// Alternative: Use ctor for automatic registration
#[cfg(feature = "auto-register")]
#[ctor::ctor]
fn auto_register() {
    register().expect("Failed to register AnalyzeTextSignificanceTool");
}

#[cfg(test)]
mod tests {
    use super::*;
    
    // Commenting out tests until MockAiClient is available
    // #[test]
    // fn test_tool_metadata() {
    //     let ai_client = Arc::new(crate::llm::MockAiClient::new());
    //     let tool = AnalyzeTextSignificanceTool::new(ai_client);
    //     
    //     assert_eq!(tool.name(), "analyze_text_significance");
    //     assert_eq!(tool.category(), ToolCategory::Analysis);
    //     assert_eq!(tool.capabilities().len(), 3);
    //     assert_eq!(tool.version(), "2.0.0");
    // }
    // 
    // #[test]
    // fn test_security_policy() {
    //     let ai_client = Arc::new(crate::llm::MockAiClient::new());
    //     let tool = AnalyzeTextSignificanceTool::new(ai_client);
    //     let policy = tool.security_policy();
    //     
    //     assert!(policy.allowed_agents.contains(&AgentType::Orchestrator));
    //     assert!(policy.allowed_agents.contains(&AgentType::Perception));
    //     assert!(!policy.data_access.write_access);
    //     assert_eq!(policy.audit_level, AuditLevel::Basic);
    // }
}