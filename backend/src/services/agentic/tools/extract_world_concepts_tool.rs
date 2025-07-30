//! AI-Powered World Concepts Extraction Tool
//!
//! This tool analyzes narrative content to extract persistent world-building
//! concepts suitable for lorebook entries: locations, factions, items, lore, etc.

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

/// Self-registering tool for AI-powered world concepts extraction
pub struct ExtractWorldConceptsTool {
    app_state: Arc<AppState>,
}

impl ExtractWorldConceptsTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
}

#[async_trait]
impl ScribeTool for ExtractWorldConceptsTool {
    fn name(&self) -> &'static str {
        "extract_world_concepts"
    }

    fn description(&self) -> &'static str {
        "AI-powered extraction of persistent world-building concepts from narrative content. Identifies locations, factions, items, lore, cultures, and other elements suitable for lorebook entries."
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
                    "description": "The narrative content to analyze for world concepts"
                },
                "context": {
                    "type": "string",
                    "description": "Optional additional context about the narrative content"
                },
                "focus_categories": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of specific categories to focus on (locations, factions, items, lore, etc.)"
                }
            },
            "required": ["user_id", "content"]
        })
    }

    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        debug!("Executing extract_world_concepts tool with Flash-powered analysis");

        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let content = params.get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("content is required".to_string()))?;

        let context = params.get("context")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let focus_categories = params.get("focus_categories")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();

        let user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        info!("Extracting world concepts for user {} from {} characters of content", 
              user_id, content.len());

        // Build focus instruction
        let focus_instruction = if focus_categories.is_empty() {
            "Extract all types of world-building concepts".to_string()
        } else {
            format!("Focus primarily on these categories: {}", focus_categories.join(", "))
        };

        // Use Flash to intelligently extract world-building concepts
        let extraction_prompt = format!(
            r#"Analyze this narrative content and extract persistent world-building concepts suitable for a lorebook.

NARRATIVE CONTENT:
{}

ADDITIONAL CONTEXT:
{}

FOCUS INSTRUCTION:
{}

EXTRACTION INSTRUCTIONS:
- Identify persistent elements that define the game world (not temporary events)
- Classify concepts into categories: LOCATION, FACTION, CULTURE, ITEM, LORE, CONCEPT, PERSON, CREATURE, MAGIC, TECHNOLOGY
- For each concept, provide detailed descriptions suitable for lorebook entries
- Identify relationships between concepts (how they connect to each other)
- Determine importance levels for prioritizing lorebook creation
- Extract cultural, historical, or magical significance
- Note any rules, laws, or systemic aspects
- Avoid temporary events or character actions (focus on persistent world state)

RESPOND WITH JSON:
{{
    "concepts": [
        {{
            "name": "string (the concept name)",
            "category": "string (LOCATION|FACTION|CULTURE|ITEM|LORE|CONCEPT|PERSON|CREATURE|MAGIC|TECHNOLOGY)",
            "subcategory": "string (more specific classification)",
            "description": "string (detailed description suitable for lorebook)",
            "significance": {{
                "importance_level": "string (CRITICAL|HIGH|MODERATE|LOW)",
                "world_impact": "string (how this affects the broader world)",
                "player_relevance": "string (why players should know about this)"
            }},
            "relationships": [
                {{
                    "related_concept": "string (name of related concept)",
                    "relationship_type": "string (CONTAINS|PART_OF|ALLIED_WITH|ENEMY_OF|CREATED_BY|CONTROLS|etc.)",
                    "description": "string (how they relate)"
                }}
            ],
            "attributes": {{
                "physical_description": "string (appearance, size, etc.)",
                "cultural_aspects": "string (traditions, beliefs, customs)",
                "historical_significance": "string (past events, origins)",
                "current_status": "string (present state in the world)",
                "special_properties": "string (magical, technological, or unique traits)"
            }},
            "lorebook_entry": {{
                "title": "string (lorebook entry title)",
                "content": "string (formatted lorebook entry content)",
                "tags": ["string (searchable tags)"],
                "visibility": "string (PUBLIC|PRIVATE|RESTRICTED)"
            }}
        }}
    ],
    "concept_network": {{
        "major_themes": ["string (overarching themes identified)"],
        "cultural_groups": ["string (cultures or societies mentioned)"],
        "geographical_regions": ["string (areas or regions)"],
        "power_structures": ["string (governments, hierarchies, factions)"],
        "belief_systems": ["string (religions, philosophies, ideologies)"]
    }},
    "extraction_summary": {{
        "total_concepts": number,
        "categories_found": ["string (categories that had concepts)"],
        "complexity_level": "string (SIMPLE|MODERATE|COMPLEX|HIGHLY_COMPLEX)",
        "world_building_depth": "string (assessment of world-building richness)"
    }},
    "analysis_method": "Flash AI world-building analysis"
}}"#,
            content,
            context,
            focus_instruction
        );

        // Define the JSON schema for structured output
        let schema = json!({
            "type": "object",
            "properties": {
                "concepts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "category": {
                                "type": "string", 
                                "enum": ["LOCATION", "FACTION", "CULTURE", "ITEM", "LORE", "CONCEPT", "PERSON", "CREATURE", "MAGIC", "TECHNOLOGY"]
                            },
                            "subcategory": {"type": "string"},
                            "description": {"type": "string"},
                            "significance": {
                                "type": "object",
                                "properties": {
                                    "importance_level": {"type": "string", "enum": ["CRITICAL", "HIGH", "MODERATE", "LOW"]},
                                    "world_impact": {"type": "string"},
                                    "player_relevance": {"type": "string"}
                                }
                            },
                            "relationships": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "related_concept": {"type": "string"},
                                        "relationship_type": {"type": "string"},
                                        "description": {"type": "string"}
                                    }
                                }
                            },
                            "attributes": {
                                "type": "object",
                                "properties": {
                                    "physical_description": {"type": "string"},
                                    "cultural_aspects": {"type": "string"},
                                    "historical_significance": {"type": "string"},
                                    "current_status": {"type": "string"},
                                    "special_properties": {"type": "string"}
                                }
                            },
                            "lorebook_entry": {
                                "type": "object",
                                "properties": {
                                    "title": {"type": "string"},
                                    "content": {"type": "string"},
                                    "tags": {"type": "array", "items": {"type": "string"}},
                                    "visibility": {"type": "string", "enum": ["PUBLIC", "PRIVATE", "RESTRICTED"]}
                                }
                            }
                        },
                        "required": ["name", "category", "description"]
                    }
                },
                "concept_network": {
                    "type": "object",
                    "properties": {
                        "major_themes": {"type": "array", "items": {"type": "string"}},
                        "cultural_groups": {"type": "array", "items": {"type": "string"}},
                        "geographical_regions": {"type": "array", "items": {"type": "string"}},
                        "power_structures": {"type": "array", "items": {"type": "string"}},
                        "belief_systems": {"type": "array", "items": {"type": "string"}}
                    }
                },
                "extraction_summary": {
                    "type": "object",
                    "properties": {
                        "total_concepts": {"type": "number"},
                        "categories_found": {"type": "array", "items": {"type": "string"}},
                        "complexity_level": {"type": "string", "enum": ["SIMPLE", "MODERATE", "COMPLEX", "HIGHLY_COMPLEX"]},
                        "world_building_depth": {"type": "string"}
                    }
                },
                "analysis_method": {"type": "string"}
            },
            "required": ["concepts", "extraction_summary", "analysis_method"]
        });

        // Use genai chat with structured output
        use genai::chat::{ChatRequest, ChatOptions, ChatResponseFormat, JsonSchemaSpec};
        
        let chat_request = ChatRequest::from_user(extraction_prompt);
        let mut chat_options = ChatOptions::default()
            .with_max_tokens(4000) // More tokens for detailed world-building extraction
            .with_temperature(0.4); // Balanced creativity for world-building
        
        // Enable structured output using JSON schema
        chat_options = chat_options.with_response_format(
            ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec { schema })
        );
        
        let response = self.app_state.ai_client
            .exec_chat(
                &self.app_state.config.fast_model, // Flash for world concept analysis
                chat_request,
                Some(chat_options),
            )
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Flash world concept analysis failed: {}", e)))?;
        
        let flash_response = response.first_content_text_as_str()
            .ok_or_else(|| ToolError::ExecutionFailed("Empty response from Flash".to_string()))?;

        // Parse Flash response as JSON
        let result: JsonValue = serde_json::from_str(&flash_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse Flash response: {}", e)))?;

        let concepts_count = result.get("concepts")
            .and_then(|c| c.as_array())
            .map(|a| a.len())
            .unwrap_or(0);

        info!("Flash world concept analysis completed for user {}, extracted {} concepts", 
              user_id, concepts_count);

        // Add metadata to the result
        let mut enhanced_result = result;
        enhanced_result["extraction_metadata"] = json!({
            "user_id": user_id,
            "content_length": content.len(),
            "concepts_extracted": concepts_count,
            "focus_categories": focus_categories,
            "analysis_timestamp": chrono::Utc::now().to_rfc3339(),
            "model_used": self.app_state.config.fast_model
        });

        Ok(enhanced_result)
    }
}

#[async_trait]
impl SelfRegisteringTool for ExtractWorldConceptsTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Analysis
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "extract".to_string(),
                target: "world concepts".to_string(),
                context: Some("for lorebook creation with detailed descriptions".to_string()),
            },
            ToolCapability {
                action: "analyze".to_string(),
                target: "world-building elements".to_string(),
                context: Some("locations, factions, items, lore, cultures".to_string()),
            },
            ToolCapability {
                action: "identify".to_string(),
                target: "concept relationships".to_string(),
                context: Some("how world elements connect and interact".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool when you have narrative content that describes world-building elements: locations, factions, cultures, items, lore, or other persistent aspects of the game world. Best for rich descriptive content that establishes world state rather than temporary events.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for temporal events or character actions (use extract_temporal_events instead), simple dialogue without world-building, or content that's purely about character development without world context.".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Extracting world concepts from a location description".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "content": "The Crystal Caverns of Aethermoor are home to the ancient Draconic Order, a sect of dragon-riding knights who guard the Shard of Eternal Flame. Their enchanted weapons are forged from starfall metal, and they follow the Code of Dragonfire. The caverns themselves are a maze of glowing crystal formations that amplify magical energy.",
                    "context": "Description of a major location and faction",
                    "focus_categories": ["LOCATION", "FACTION", "ITEM", "LORE"]
                }),
                expected_output: "Returns structured concepts: Crystal Caverns (LOCATION), Draconic Order (FACTION), Shard of Eternal Flame (ITEM), starfall metal (ITEM), Code of Dragonfire (LORE), with relationships and lorebook entries".to_string(),
            }
        ]
    }

    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
            ],
            required_capabilities: vec!["narrative_analysis".to_string(), "lorebook_access".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false, // Read-only analysis tool
                allowed_scopes: vec!["narratives".to_string(), "lorebook".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 150, // Higher memory for complex world-building analysis
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Flash API calls
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "concepts": {
                    "type": "array",
                    "description": "Array of extracted world-building concepts"
                },
                "concept_network": {
                    "type": "object",
                    "description": "High-level analysis of world-building themes and structures"
                },
                "extraction_summary": {
                    "type": "object",
                    "description": "Summary statistics and assessment of the extraction"
                },
                "extraction_metadata": {
                    "type": "object",
                    "description": "Metadata about the extraction process"
                },
                "analysis_method": {"type": "string"}
            },
            "required": ["concepts", "extraction_summary", "analysis_method"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "flash".to_string(),
            "world-building".to_string(),
            "lorebook".to_string(),
            "concepts".to_string(),
            "extraction".to_string(),
            "relationships".to_string(),
        ]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "NO_WORLD_CONCEPTS".to_string(),
                description: "No persistent world-building concepts could be identified in the content".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "EXTRACTION_FAILED".to_string(),
                description: "Flash AI analysis failed to extract world concepts".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "INSUFFICIENT_WORLD_BUILDING".to_string(),
                description: "Content lacks sufficient world-building elements for extraction".to_string(),
                retry_able: false,
            },
        ]
    }
}

/// Registration function for the tool
pub fn register_extract_world_concepts_tool(app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    let tool = Arc::new(ExtractWorldConceptsTool::new(app_state)) as Arc<dyn SelfRegisteringTool>;
    UnifiedToolRegistry::register_if_not_exists(tool)?;
    
    Ok(())
}