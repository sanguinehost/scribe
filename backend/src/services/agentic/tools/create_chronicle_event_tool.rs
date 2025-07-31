//! AI-Powered Chronicle Event Creation Tool
//!
//! This tool creates structured chronicle events from narrative summaries,
//! handling actor extraction, event type classification, and temporal data.

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
    models::chronicle_event::{CreateEventRequest, EventSource},
    auth::session_dek::SessionDek,
    state::AppState,
};

/// Self-registering tool for AI-powered chronicle event creation
pub struct CreateChronicleEventTool {
    app_state: Arc<AppState>,
}

impl CreateChronicleEventTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
}

#[async_trait]
impl ScribeTool for CreateChronicleEventTool {
    fn name(&self) -> &'static str {
        "create_chronicle_event"
    }

    fn description(&self) -> &'static str {
        "AI-powered creation of structured chronicle events. Extracts actors, classifies event types, and creates temporal records with proper narrative structure."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user creating the event"
                },
                "chronicle_id": {
                    "type": "string",
                    "description": "The UUID of the chronicle to add the event to"
                },
                "summary": {
                    "type": "string",
                    "description": "The narrative summary describing what happened"
                },
                "event_type": {
                    "type": "string",
                    "description": "Optional hierarchical event type (e.g., COMBAT.ENCOUNTER.DRAGON_BATTLE)"
                },
                "context": {
                    "type": "string",
                    "description": "Optional additional context about the event"
                }
            },
            "required": ["user_id", "chronicle_id", "summary"]
        })
    }

    async fn execute(&self, params: &ToolParams, session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        debug!("Executing create_chronicle_event tool with Flash-powered analysis");

        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let chronicle_id_str = params.get("chronicle_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("chronicle_id is required".to_string()))?;

        let summary = params.get("summary")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("summary is required".to_string()))?;

        let event_type = params.get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("NARRATIVE.EVENT.GENERAL");

        let context = params.get("context")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let chronicle_id = Uuid::parse_str(chronicle_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid chronicle_id format".to_string()))?;

        info!("Creating chronicle event for user {} in chronicle {} with type {}", 
              user_id, chronicle_id, event_type);

        // Use Flash to intelligently extract actors and structure the event
        let analysis_prompt = format!(
            r#"Analyze this narrative summary and extract structured event data for chronicle creation.

NARRATIVE SUMMARY:
{}

EVENT TYPE: {}

ADDITIONAL CONTEXT:
{}

ANALYSIS INSTRUCTIONS:
- Extract all actors involved (characters, entities, objects that perform actions)
- Classify each actor's role: AGENT (active performer), PATIENT (receives action), INSTRUMENT (tool/means), LOCATION (where it happens)
- Identify the primary action/verb that defines this event
- Determine spatial context (locations, environments)
- Assess temporal context (sequence, duration, timing indicators)
- Generate a concise but complete event description
- Extract key narrative elements for metadata

RESPOND WITH JSON:
{{
    "actors": [
        {{
            "name": "string (actor name)",
            "role": "string (AGENT|PATIENT|INSTRUMENT|LOCATION)",
            "entity_type": "string (CHARACTER|LOCATION|ITEM|CONCEPT)",
            "description": "string (brief description if needed)"
        }}
    ],
    "action": "string (primary action/verb describing what happened)",
    "event_description": "string (structured chronicle description)",
    "spatial_context": {{
        "primary_location": "string (main location)",
        "secondary_locations": ["string (other locations mentioned)"],
        "spatial_relationships": "string (how locations relate)"
    }},
    "temporal_context": {{
        "sequence_indicators": ["string (words like 'first', 'then', 'finally')"],
        "duration_hints": "string (timing clues)",
        "temporal_relationships": "string (how this relates to other events)"
    }},
    "metadata": {{
        "significance_level": "string (MAJOR|MODERATE|MINOR)",
        "narrative_themes": ["string (themes like 'conflict', 'discovery', 'growth')"],
        "emotional_tone": "string (overall emotional context)",
        "consequences": "string (implied or explicit outcomes)"
    }},
    "analysis_method": "Flash AI analysis"
}}"#,
            summary,
            event_type,
            context
        );

        // Define the JSON schema for structured output
        let schema = json!({
            "type": "object",
            "properties": {
                "actors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "role": {"type": "string", "enum": ["AGENT", "PATIENT", "INSTRUMENT", "LOCATION"]},
                            "entity_type": {"type": "string", "enum": ["CHARACTER", "LOCATION", "ITEM", "CONCEPT"]},
                            "description": {"type": "string"}
                        },
                        "required": ["name", "role", "entity_type"]
                    }
                },
                "action": {"type": "string"},
                "event_description": {"type": "string"},
                "spatial_context": {
                    "type": "object",
                    "properties": {
                        "primary_location": {"type": "string"},
                        "secondary_locations": {"type": "array", "items": {"type": "string"}},
                        "spatial_relationships": {"type": "string"}
                    }
                },
                "temporal_context": {
                    "type": "object",
                    "properties": {
                        "sequence_indicators": {"type": "array", "items": {"type": "string"}},
                        "duration_hints": {"type": "string"},
                        "temporal_relationships": {"type": "string"}
                    }
                },
                "metadata": {
                    "type": "object",
                    "properties": {
                        "significance_level": {"type": "string", "enum": ["MAJOR", "MODERATE", "MINOR"]},
                        "narrative_themes": {"type": "array", "items": {"type": "string"}},
                        "emotional_tone": {"type": "string"},
                        "consequences": {"type": "string"}
                    }
                },
                "analysis_method": {"type": "string"}
            },
            "required": ["actors", "action", "event_description", "analysis_method"]
        });

        // Use genai chat with structured output
        use genai::chat::{ChatRequest, ChatOptions, ChatResponseFormat, JsonSchemaSpec};
        
        let chat_request = ChatRequest::from_user(analysis_prompt);
        let mut chat_options = ChatOptions::default()
            .with_max_tokens(2000)
            .with_temperature(0.4); // Balanced creativity for event structuring
        
        // Enable structured output using JSON schema
        chat_options = chat_options.with_response_format(
            ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec { schema })
        );
        
        let response = self.app_state.ai_client
            .exec_chat(
                &self.app_state.config.fast_model, // Flash for event analysis
                chat_request,
                Some(chat_options),
            )
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Flash event analysis failed: {}", e)))?;
        
        let flash_response = response.first_content_text_as_str()
            .ok_or_else(|| ToolError::ExecutionFailed("Empty response from Flash".to_string()))?;

        // Parse Flash response as JSON
        let analysis: JsonValue = serde_json::from_str(&flash_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse Flash response: {}", e)))?;

        // Extract structured data
        let actors = analysis.get("actors").and_then(|a| a.as_array()).cloned().unwrap_or_default();
        let action = analysis.get("action").and_then(|a| a.as_str()).unwrap_or("occurred").to_string();
        let event_description = analysis.get("event_description").and_then(|d| d.as_str()).unwrap_or(summary).to_string();
        
        // Create event metadata from analysis
        let mut event_metadata = json!({
            "actors": actors,
            "action": action,
            "spatial_context": analysis.get("spatial_context").cloned().unwrap_or(json!({})),
            "temporal_context": analysis.get("temporal_context").cloned().unwrap_or(json!({})),
            "significance_metadata": analysis.get("metadata").cloned().unwrap_or(json!({})),
            "original_summary": summary,
            "event_type_hierarchy": event_type,
            "analysis_method": "Flash AI analysis"
        });

        // Add context if provided
        if !context.is_empty() {
            event_metadata["additional_context"] = json!(context);
        }

        // Create the chronicle event using the chronicle service
        let event_request = CreateEventRequest {
            event_type: event_type.to_string(),
            summary: event_description.clone(),
            source: EventSource::AiExtracted,
            event_data: Some(event_metadata),
            timestamp_iso8601: None,
        };
        
        let event_result = self.app_state.chronicle_service
            .create_event(user_id, chronicle_id, event_request, Some(session_dek))
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to create chronicle event: {}", e)))?;

        info!("Successfully created chronicle event {} for user {}", event_result.id, user_id);

        Ok(json!({
            "status": "success",
            "message": "Chronicle event created successfully",
            "event_id": event_result.id,
            "event_type": event_type,
            "action": action,
            "actors": actors,
            "sequence_number": event_result.sequence_number,
            "description": event_description,
            "analysis_quality": "Flash AI enhanced"
        }))
    }
}

#[async_trait]
impl SelfRegisteringTool for CreateChronicleEventTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Creation
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "create".to_string(),
                target: "chronicle event".to_string(),
                context: Some("with AI-powered actor extraction and event structuring".to_string()),
            },
            ToolCapability {
                action: "analyze".to_string(),
                target: "narrative summaries".to_string(),
                context: Some("for temporal event creation".to_string()),
            },
            ToolCapability {
                action: "extract".to_string(),
                target: "actors and actions".to_string(),
                context: Some("from narrative text".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool to create structured chronicle events from narrative summaries. It intelligently extracts actors, actions, and contextual information to create well-structured temporal records.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for creating lorebook entries (use create_lorebook_entry), updating existing events, or when you need to analyze multiple events simultaneously.".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Creating a combat event in the chronicle".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "chronicle_id": "456e7890-e89b-12d3-a456-426614174001",
                    "summary": "Sir Gareth defeated the Ancient Red Dragon in the village square using his enchanted sword.",
                    "event_type": "COMBAT.ENCOUNTER.DRAGON_BATTLE",
                    "context": "This was the climactic battle that saved the village"
                }),
                expected_output: "Returns success confirmation with structured event data, extracted actors (Sir Gareth as AGENT, Ancient Red Dragon as PATIENT), and chronicle metadata".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Chronicler,  // ONLY Chronicler Agent can create chronicle events
            ],
            required_capabilities: vec!["chronicle_write".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true, // Creates chronicle events
                allowed_scopes: vec!["chronicles".to_string()],
            },
            audit_level: AuditLevel::Full, // Full audit for chronicle creation
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 75,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Flash API calls
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "message": {"type": "string"},
                "event_id": {"type": "string"},
                "event_type": {"type": "string"},
                "action": {"type": "string"},
                "actors": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "role": {"type": "string"},
                            "entity_type": {"type": "string"}
                        }
                    }
                },
                "sequence_number": {"type": "integer"},
                "description": {"type": "string"},
                "analysis_quality": {"type": "string"}
            },
            "required": ["status", "event_id", "event_type"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "flash".to_string(),
            "chronicle".to_string(),
            "creation".to_string(),
            "temporal".to_string(),
            "events".to_string(),
            "narrative".to_string(),
        ]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "INVALID_CHRONICLE".to_string(),
                description: "The specified chronicle does not exist or is not accessible".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "EVENT_CREATION_FAILED".to_string(),
                description: "Failed to create the chronicle event in the database".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "ANALYSIS_FAILED".to_string(),
                description: "Flash AI analysis failed to extract event structure".to_string(),
                retry_able: true,
            },
        ]
    }
}

/// Registration function for the tool
pub fn register_create_chronicle_event_tool(app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    let tool = Arc::new(CreateChronicleEventTool::new(app_state)) as Arc<dyn SelfRegisteringTool>;
    UnifiedToolRegistry::register_if_not_exists(tool)?;
    
    Ok(())
}