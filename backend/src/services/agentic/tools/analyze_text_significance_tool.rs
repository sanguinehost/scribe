//! AI-Powered Text Significance Analysis Tool
//!
//! This tool analyzes narrative text to determine if it contains significant events,
//! character development, or world changes worth recording in the chronicle.

use std::sync::Arc;
use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use uuid::Uuid;
use tracing::{info, debug};

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
    state::AppState,
};

/// Self-registering tool for AI-powered narrative significance analysis
pub struct AnalyzeTextSignificanceTool {
    app_state: Arc<AppState>,
}

impl AnalyzeTextSignificanceTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
}

#[async_trait]
impl ScribeTool for AnalyzeTextSignificanceTool {
    fn name(&self) -> &'static str {
        "analyze_text_significance"
    }

    fn description(&self) -> &'static str {
        "AI-powered analysis to determine if narrative content contains significant events worth recording. Uses Flash-Lite for intelligent triage analysis replacing hardcoded rules."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user requesting analysis"
                },
                "content": {
                    "type": "string",
                    "description": "The narrative content to analyze for significance"
                }
            },
            "required": ["user_id", "content"]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        debug!("Executing analyze_text_significance tool with proper structured output");

        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let content = params.get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("content is required".to_string()))?;

        let user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        info!("Starting Flash-Lite significance analysis for user {} with {} characters", 
              user_id, content.len());

        // Create analysis prompt for structured output
        let analysis_prompt = format!(
            r#"Analyze the following narrative content for significance. Determine if it contains events worth recording in a game chronicle.

CONTENT TO ANALYZE:
{}

ANALYSIS INSTRUCTIONS:
- Assess narrative significance (major events, character development, world changes, plot progression)
- Provide confidence score (0.0-1.0) based on content richness and event importance
- Classify event type using hierarchical taxonomy: CATEGORY.TYPE.SUBTYPE
- Extract key entities mentioned (characters, locations, items)
- Generate concise summary of significant elements

RESPOND WITH JSON:
{{
    "is_significant": boolean,
    "confidence": number,
    "event_type": "string (e.g., CHARACTER.DEVELOPMENT.GROWTH)",
    "summary": "string (concise summary)",
    "reasoning": "string (explanation of significance)",
    "extracted_entities": ["entity1", "entity2"],
    "analysis_method": "Flash-Lite AI analysis"
}}"#,
            content
        );

        // Define the JSON schema for structured output
        let schema = json!({
            "type": "object",
            "properties": {
                "is_significant": {
                    "type": "boolean",
                    "description": "Whether the content contains significant narrative events"
                },
                "confidence": {
                    "type": "number",
                    "minimum": 0.0,
                    "maximum": 1.0,
                    "description": "Confidence score for the significance assessment"
                },
                "event_type": {
                    "type": "string",
                    "description": "Hierarchical event type classification (e.g., CHARACTER.DEVELOPMENT.GROWTH)"
                },
                "summary": {
                    "type": "string",
                    "description": "Concise summary of significant elements"
                },
                "reasoning": {
                    "type": "string",
                    "description": "Explanation of significance assessment"
                },
                "extracted_entities": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Key entities mentioned in the content"
                },
                "analysis_method": {
                    "type": "string",
                    "description": "Analysis method used"
                }
            },
            "required": ["is_significant", "confidence", "event_type", "summary", "reasoning", "extracted_entities", "analysis_method"]
        });

        // Use genai chat with structured output
        use genai::chat::{ChatRequest, ChatOptions, ChatResponseFormat, JsonSchemaSpec};
        
        let chat_request = ChatRequest::from_user(analysis_prompt);
        let mut chat_options = ChatOptions::default()
            .with_max_tokens(1000)
            .with_temperature(0.3); // Low temperature for consistent analysis
        
        // Enable structured output using JSON schema
        chat_options = chat_options.with_response_format(
            ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec { schema })
        );
        
        let response = self.app_state.ai_client
            .exec_chat(
                &self.app_state.config.fast_model, // Flash-Lite for fast triage
                chat_request,
                Some(chat_options),
            )
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Flash-Lite analysis failed: {}", e)))?;
        
        let flash_response = response.first_content_text_as_str()
            .ok_or_else(|| ToolError::ExecutionFailed("Empty response from Flash-Lite".to_string()))?;

        // Parse Flash-Lite response as JSON
        let result: JsonValue = serde_json::from_str(&flash_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse Flash-Lite response: {}", e)))?;

        info!("Flash-Lite significance analysis completed with confidence: {}", 
              result.get("confidence").and_then(|c| c.as_f64()).unwrap_or(0.0));

        Ok(result)
    }
}

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
                context: Some("for significance and event detection".to_string()),
            },
            ToolCapability {
                action: "assess".to_string(),
                target: "content".to_string(),
                context: Some("narrative importance".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool when you need to determine if narrative content contains significant events, character development, or world changes worth recording in the chronicle. Essential for narrative triage and filtering.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for already processed content, non-narrative text, or when you need to extract specific events (use extract_temporal_events instead).".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Analyzing a conversation for chronicle-worthy events".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "content": "The dragon appeared suddenly, breathing fire across the village square. Sir Gareth raised his shield and charged forward, striking the beast with his enchanted sword."
                }),
                expected_output: "Returns significance analysis with high confidence score and event type classification".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Perception,  // Primary analyzer
                AgentType::Strategic,   // Can analyze for planning
                AgentType::Chronicler,  // Can analyze for event creation
            ],
            required_capabilities: vec!["narrative_analysis".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false,
                allowed_scopes: vec!["narratives".to_string(), "analysis".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 50,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Flash-Lite API calls
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "is_significant": {"type": "boolean"},
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "event_type": {"type": "string"},
                "summary": {"type": "string"},
                "reasoning": {"type": "string"},
                "extracted_entities": {"type": "array", "items": {"type": "string"}},
                "analysis_method": {"type": "string"}
            },
            "required": ["is_significant", "confidence", "analysis_method"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "flash-lite".to_string(),
            "narrative".to_string(),
            "significance".to_string(),
            "triage".to_string(),
        ]
    }
}

/// Registration function for the tool
pub fn register_analyze_text_significance_tool(app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    let tool = Arc::new(AnalyzeTextSignificanceTool::new(app_state)) as Arc<dyn SelfRegisteringTool>;
    UnifiedToolRegistry::register_if_not_exists(tool)?;
    
    Ok(())
}