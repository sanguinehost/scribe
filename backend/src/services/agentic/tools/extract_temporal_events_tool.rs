//! AI-Powered Temporal Events Extraction Tool
//!
//! This tool analyzes narrative content to extract multiple discrete temporal events
//! with their causality chains, actor relationships, and chronological ordering.

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

/// Self-registering tool for AI-powered temporal events extraction
pub struct ExtractTemporalEventsTool {
    app_state: Arc<AppState>,
}

impl ExtractTemporalEventsTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
}

#[async_trait]
impl ScribeTool for ExtractTemporalEventsTool {
    fn name(&self) -> &'static str {
        "extract_temporal_events"
    }

    fn description(&self) -> &'static str {
        "AI-powered extraction of multiple discrete temporal events from complex narrative content. Identifies chronological sequences, causality chains, and actor relationships across multiple events."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user requesting extraction"
                },
                "content": {
                    "type": "string",
                    "description": "The narrative content to analyze for temporal events"
                },
                "context": {
                    "type": "string",
                    "description": "Optional additional context about the narrative content"
                }
            },
            "required": ["user_id", "content"]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        debug!("Executing extract_temporal_events tool with Flash-powered analysis");

        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let content = params.get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("content is required".to_string()))?;

        let context = params.get("context")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        info!("Extracting temporal events for user {} from {} characters of content", 
              user_id, content.len());

        // Use Flash to intelligently extract discrete temporal events
        let extraction_prompt = format!(
            r#"Analyze this narrative content and extract discrete temporal events in chronological order.

NARRATIVE CONTENT:
{}

ADDITIONAL CONTEXT:
{}

EXTRACTION INSTRUCTIONS:
- Identify separate, discrete events that happen at different moments in time
- For each event, extract actors (who), actions (what), locations (where), and temporal markers (when)
- Classify each actor's role: AGENT (performs action), PATIENT (receives action), INSTRUMENT (tool used), LOCATION (where it happens)
- Identify causality relationships between events (how one event leads to another)
- Determine chronological sequence using temporal markers and narrative flow
- Extract spatial context for each event
- Classify event types using hierarchical taxonomy
- Note any parallel or simultaneous events

RESPOND WITH JSON:
{{
    "events": [
        {{
            "sequence_order": number,
            "event_type": "string (hierarchical classification like COMBAT.ACTION.ATTACK)",
            "summary": "string (concise description of what happened)",
            "actors": [
                {{
                    "name": "string",
                    "role": "string (AGENT|PATIENT|INSTRUMENT|LOCATION)",
                    "entity_type": "string (CHARACTER|LOCATION|ITEM|CONCEPT)"
                }}
            ],
            "action": "string (primary verb/action)",
            "temporal_context": {{
                "sequence_markers": ["string (words indicating sequence like 'first', 'then')"],
                "duration_hints": "string (time indicators)",
                "relative_timing": "string (how this relates temporally to other events)"
            }},
            "spatial_context": {{
                "primary_location": "string",
                "movement": "string (any movement or location changes)",
                "spatial_relationships": "string"
            }},
            "causality": {{
                "causes": ["number (sequence_order of events that caused this)"],
                "effects": ["number (sequence_order of events this caused)"],
                "causal_relationship": "string (description of how events connect)"
            }},
            "significance": {{
                "importance_level": "string (MAJOR|MODERATE|MINOR)",
                "narrative_impact": "string (how this affects the story)",
                "emotional_weight": "string"
            }}
        }}
    ],
    "chronological_summary": "string (overall timeline description)",
    "causal_chains": [
        {{
            "chain_description": "string",
            "event_sequence": ["number (sequence_orders in causal order)"]
        }}
    ],
    "parallel_events": [
        {{
            "description": "string",
            "simultaneous_events": ["number (sequence_orders of events happening at same time)"]
        }}
    ],
    "analysis_method": "Flash AI temporal analysis"
}}"#,
            content,
            context
        );

        // Define the JSON schema for structured output
        let schema = json!({
            "type": "object",
            "properties": {
                "events": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "sequence_order": {"type": "number"},
                            "event_type": {"type": "string"},
                            "summary": {"type": "string"},
                            "actors": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "role": {"type": "string", "enum": ["AGENT", "PATIENT", "INSTRUMENT", "LOCATION"]},
                                        "entity_type": {"type": "string", "enum": ["CHARACTER", "LOCATION", "ITEM", "CONCEPT"]}
                                    },
                                    "required": ["name", "role", "entity_type"]
                                }
                            },
                            "action": {"type": "string"},
                            "temporal_context": {
                                "type": "object",
                                "properties": {
                                    "sequence_markers": {"type": "array", "items": {"type": "string"}},
                                    "duration_hints": {"type": "string"},
                                    "relative_timing": {"type": "string"}
                                }
                            },
                            "spatial_context": {
                                "type": "object",
                                "properties": {
                                    "primary_location": {"type": "string"},
                                    "movement": {"type": "string"},
                                    "spatial_relationships": {"type": "string"}
                                }
                            },
                            "causality": {
                                "type": "object",
                                "properties": {
                                    "causes": {"type": "array", "items": {"type": "number"}},
                                    "effects": {"type": "array", "items": {"type": "number"}},
                                    "causal_relationship": {"type": "string"}
                                }
                            },
                            "significance": {
                                "type": "object",
                                "properties": {
                                    "importance_level": {"type": "string", "enum": ["MAJOR", "MODERATE", "MINOR"]},
                                    "narrative_impact": {"type": "string"},
                                    "emotional_weight": {"type": "string"}
                                }
                            }
                        },
                        "required": ["sequence_order", "event_type", "summary", "actors", "action"]
                    }
                },
                "chronological_summary": {"type": "string"},
                "causal_chains": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "chain_description": {"type": "string"},
                            "event_sequence": {"type": "array", "items": {"type": "number"}}
                        }
                    }
                },
                "parallel_events": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "description": {"type": "string"},
                            "simultaneous_events": {"type": "array", "items": {"type": "number"}}
                        }
                    }
                },
                "analysis_method": {"type": "string"}
            },
            "required": ["events", "chronological_summary", "analysis_method"]
        });

        // Use genai chat with structured output
        use genai::chat::{ChatRequest, ChatOptions, ChatResponseFormat, JsonSchemaSpec};
        
        let chat_request = ChatRequest::from_user(extraction_prompt);
        let mut chat_options = ChatOptions::default()
            .with_max_tokens(3000) // More tokens for complex event extraction
            .with_temperature(0.3); // Low temperature for consistent analysis
        
        // Enable structured output using JSON schema
        chat_options = chat_options.with_response_format(
            ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec { schema })
        );
        
        let response = self.app_state.ai_client
            .exec_chat(
                &self.app_state.config.fast_model, // Flash for temporal analysis
                chat_request,
                Some(chat_options),
            )
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Flash temporal analysis failed: {}", e)))?;
        
        let flash_response = response.first_content_text_as_str()
            .ok_or_else(|| ToolError::ExecutionFailed("Empty response from Flash".to_string()))?;

        // Parse Flash response as JSON
        let result: JsonValue = serde_json::from_str(&flash_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse Flash response: {}", e)))?;

        let events_count = result.get("events")
            .and_then(|e| e.as_array())
            .map(|a| a.len())
            .unwrap_or(0);

        info!("Flash temporal analysis completed for user {}, extracted {} events", 
              user_id, events_count);

        // Add metadata to the result
        let mut enhanced_result = result;
        enhanced_result["extraction_metadata"] = json!({
            "user_id": user_id,
            "content_length": content.len(),
            "events_extracted": events_count,
            "analysis_timestamp": chrono::Utc::now().to_rfc3339(),
            "model_used": self.app_state.config.fast_model
        });

        Ok(enhanced_result)
    }
}

#[async_trait]
impl SelfRegisteringTool for ExtractTemporalEventsTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "extract".to_string(),
                target: "temporal events".to_string(),
                context: Some("with chronological ordering and causality analysis".to_string()),
            },
            ToolCapability {
                action: "analyze".to_string(),
                target: "causality chains".to_string(),
                context: Some("between discrete narrative events".to_string()),
            },
            ToolCapability {
                action: "identify".to_string(),
                target: "actors and actions".to_string(),
                context: Some("across multiple temporal sequences".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool when you have complex narrative content containing multiple discrete events that need to be extracted, ordered chronologically, and analyzed for causal relationships. Best for sequences of actions, battles, conversations with multiple exchanges, or any multi-step narrative.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for single-event content (use analyze_text_significance first), static descriptions without temporal progression, or when you need world-building concepts rather than temporal events.".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Extracting events from a complex battle sequence".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "content": "First, the dragon landed on the tower with a thunderous crash. The guards immediately raised the alarm, shouting warnings across the courtyard. Then Sir Gareth charged across the stone courtyard, his armor clanking. The dragon breathed fire in response, but Gareth dodged behind his enchanted shield. Finally, he struck the killing blow with his sword, and the dragon collapsed.",
                    "context": "Epic battle sequence in the castle courtyard"
                }),
                expected_output: "Returns structured array of 5+ temporal events with causality chains, actor roles, and chronological ordering".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Perception,  // Primary extractor of temporal events
                AgentType::Chronicler,  // Can extract for chronicle creation
            ],
            required_capabilities: vec!["narrative_analysis".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false, // Read-only analysis tool
                allowed_scopes: vec!["narratives".to_string(), "analysis".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 100, // Higher memory for complex temporal analysis
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Flash API calls
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "events": {
                    "type": "array",
                    "description": "Array of extracted temporal events in chronological order"
                },
                "chronological_summary": {
                    "type": "string",
                    "description": "Overall timeline description"
                },
                "causal_chains": {
                    "type": "array",
                    "description": "Identified causality relationships between events"
                },
                "parallel_events": {
                    "type": "array", 
                    "description": "Events that happen simultaneously"
                },
                "extraction_metadata": {
                    "type": "object",
                    "description": "Metadata about the extraction process"
                },
                "analysis_method": {"type": "string"}
            },
            "required": ["events", "chronological_summary", "analysis_method"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "flash".to_string(),
            "temporal".to_string(),
            "extraction".to_string(),
            "causality".to_string(),
            "chronology".to_string(),
            "events".to_string(),
            "narrative".to_string(),
        ]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "NO_TEMPORAL_EVENTS".to_string(),
                description: "No discrete temporal events could be identified in the content".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "EXTRACTION_FAILED".to_string(),
                description: "Flash AI analysis failed to extract temporal structure".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "COMPLEX_CONTENT_LIMIT".to_string(),
                description: "Content is too complex for effective temporal extraction".to_string(),
                retry_able: false,
            },
        ]
    }
}

/// Registration function for the tool
pub fn register_extract_temporal_events_tool(app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    let tool = Arc::new(ExtractTemporalEventsTool::new(app_state)) as Arc<dyn SelfRegisteringTool>;
    UnifiedToolRegistry::register_if_not_exists(tool)?;
    
    Ok(())
}