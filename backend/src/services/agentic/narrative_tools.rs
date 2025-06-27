//! Narrative tool implementations for the agentic framework.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    llm::{EmbeddingClient, AiClient},
    services::{
        embeddings::{ChatMessageChunkMetadata, LorebookChunkMetadata, ChronicleEventMetadata},
        ChronicleService, LorebookService,
    },
    state::AppState,
    vector_db::qdrant_client::QdrantClientServiceTrait,
};

use super::tools::{ScribeTool, ToolError, ToolParams, ToolResult};

/// Tool for creating a single chronicle event (atomic operation)
pub struct CreateChronicleEventTool {
    chronicle_service: Arc<ChronicleService>,
}

impl CreateChronicleEventTool {
    pub fn new(chronicle_service: Arc<ChronicleService>) -> Self {
        Self {
            chronicle_service,
        }
    }
}

#[async_trait]
impl ScribeTool for CreateChronicleEventTool {
    fn name(&self) -> &'static str {
        "create_chronicle_event"
    }

    fn description(&self) -> &'static str {
        "Creates a single chronicle event. Use this for recording discrete temporal events that happened at a specific time in the game world. Examples: combat outcomes, character deaths, major plot developments, player actions with consequences."
    }

    fn input_schema(&self) -> Value {
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
                "event_category": {
                    "type": "string",
                    "enum": ["WORLD", "CHARACTER", "PLOT", "RELATIONSHIP"],
                    "description": "High-level category representing the primary narrative pillar affected"
                },
                "event_type": {
                    "type": "string",
                    "enum": [
                        "DISCOVERY",
                        "ALTERATION", 
                        "LORE_EXPANSION",
                        "STATE_CHANGE",
                        "DEVELOPMENT",
                        "INVENTORY_CHANGE",
                        "PROGRESSION",
                        "REVELATION",
                        "TURNING_POINT",
                        "FORMATION",
                        "MODIFICATION",
                        "INTERACTION"
                    ],
                    "description": "Abstract event category describing what type of change occurred"
                },
                "event_subtype": {
                    "type": "string",
                    "enum": [
                        "LOCATION_DISCOVERY",
                        "WORLD_CHANGE",
                        "WORLD_KNOWLEDGE",
                        "CHARACTER_DEATH",
                        "CHARACTER_INJURY",
                        "CHARACTER_GROWTH",
                        "POWER_GAINED",
                        "TRANSFORMATION",
                        "ITEM_ACQUISITION",
                        "QUEST_PROGRESS",
                        "PLOT_DEVELOPMENT",
                        "SECRET_REVELATION",
                        "DECISION_POINT",
                        "CHARACTER_MET",
                        "RELATIONSHIP_CHANGE",
                        "SOCIAL_INTERACTION",
                        "COMBAT_ENCOUNTER",
                        "EXPLORATION"
                    ],
                    "description": "Specific event subtype providing detailed classification"
                },
                "summary": {
                    "type": "string",
                    "description": "A concise summary of what happened (optional - can be auto-generated from event_data.description or other fields)"
                },
                "subject": {
                    "type": "string",
                    "description": "Primary entity initiating or experiencing the event"
                },
                "object": {
                    "type": "string",
                    "description": "Entity being acted upon (optional)"
                },
                "involved_entities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Other characters, items, or locations relevant to the event"
                },
                "event_data": {
                    "type": "object",
                    "description": "Additional structured data about the event",
                    "properties": {
                        "location": {
                            "type": "string",
                            "description": "Where the event took place"
                        },
                        "details": {
                            "type": "string",
                            "description": "Additional context or details"
                        },
                        "intensity": {
                            "type": "string",
                            "enum": ["MINOR", "MODERATE", "MAJOR", "CRITICAL"],
                            "description": "Significance level of the event"
                        }
                    }
                }
            },
            "required": ["user_id", "chronicle_id", "event_category", "event_type", "event_subtype", "subject"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing create_chronicle_event tool with params: {}", params);

        // Extract required parameters
        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let chronicle_id_str = params.get("chronicle_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("chronicle_id is required".to_string()))?;

        let event_category = params.get("event_category")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("event_category is required".to_string()))?;

        let event_type = params.get("event_type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("event_type is required".to_string()))?;

        let event_subtype = params.get("event_subtype")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("event_subtype is required".to_string()))?;

        // Try to get summary from params, or generate one from event_data or other fields
        let summary = params.get("summary")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                // Try to extract from event_data.description
                params.get("event_data")
                    .and_then(|v| v.as_object())
                    .and_then(|obj| obj.get("description"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .or_else(|| {
                // Generate a basic summary from the event components
                let subject = params.get("subject").and_then(|v| v.as_str()).unwrap_or("Someone");
                let object = params.get("object").and_then(|v| v.as_str()).unwrap_or("something");
                Some(format!("{} performed {} action on {}", subject, event_type.to_lowercase(), object))
            })
            .ok_or_else(|| ToolError::InvalidParams("summary is required (either directly or in event_data.description)".to_string()))?;

        let subject = params.get("subject")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("subject is required".to_string()))?;

        // Optional parameters
        let object = params.get("object").and_then(|v| v.as_str());
        let involved_entities = params.get("involved_entities")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();
        let event_data = params.get("event_data").cloned();

        // Parse UUIDs
        let user_uuid = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let chronicle_uuid = Uuid::parse_str(chronicle_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid chronicle_id format".to_string()))?;

        // Create hierarchical event type for storage (encode hierarchy in single field for now)
        let hierarchical_event_type = format!("{}:{}:{}", event_category, event_type, event_subtype);

        // Build enhanced event_data with entity information
        let mut enhanced_event_data = if let Some(data) = event_data {
            data.as_object().cloned().unwrap_or_default()
        } else {
            serde_json::Map::new()
        };

        // Add hierarchical metadata
        enhanced_event_data.insert("category".to_string(), json!(event_category));
        enhanced_event_data.insert("type".to_string(), json!(event_type)); 
        enhanced_event_data.insert("subtype".to_string(), json!(event_subtype));
        enhanced_event_data.insert("subject".to_string(), json!(subject));
        
        if let Some(obj) = object {
            enhanced_event_data.insert("object".to_string(), json!(obj));
        }
        
        if !involved_entities.is_empty() {
            enhanced_event_data.insert("involved_entities".to_string(), json!(involved_entities));
        }

        let create_request = crate::models::CreateEventRequest {
            event_type: hierarchical_event_type,
            summary: summary.to_string(),
            source: crate::models::EventSource::AiExtracted,
            event_data: Some(json!(enhanced_event_data)),
        };

        info!(
            "Creating hierarchical chronicle event '{}' ({}:{}:{}) for chronicle {}",
            summary,
            event_category,
            event_type, 
            event_subtype,
            chronicle_uuid
        );

        // Extract session_dek for encryption (SECURITY CRITICAL!)
        let session_dek = params.get("session_dek")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("session_dek is required for encryption".to_string()))?;
        
        // Decode the hex-encoded session_dek back to SecretBox
        let session_dek_bytes = hex::decode(session_dek)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid session_dek hex encoding: {}", e)))?;
        let session_dek_secret = secrecy::SecretBox::new(Box::new(session_dek_bytes));
        let session_dek_wrapper = crate::auth::session_dek::SessionDek(session_dek_secret);

        // Execute the atomic creation with proper encryption
        match self.chronicle_service.create_event(
            user_uuid,
            chronicle_uuid,
            create_request,
            Some(&session_dek_wrapper), // Pass SessionDek for AI-generated events encryption
        ).await {
            Ok(event) => {
                info!("Successfully created chronicle event: {}", event.id);
                Ok(json!({
                    "success": true,
                    "event_id": event.id,
                    "category": event_category,
                    "type": event_type,
                    "subtype": event_subtype,
                    "subject": subject,
                    "message": "Hierarchical chronicle event created successfully"
                }))
            }
            Err(e) => {
                error!("Failed to create chronicle event: {}", e);
                Err(ToolError::AppError(e))
            }
        }
    }
}

/// Tool for analyzing text significance (Step 1: Triage)
pub struct AnalyzeTextSignificanceTool {
    ai_client: Arc<dyn AiClient>,
}

impl AnalyzeTextSignificanceTool {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self { ai_client }
    }
}

#[async_trait]
impl ScribeTool for AnalyzeTextSignificanceTool {
    fn name(&self) -> &'static str {
        "analyze_text_significance"
    }

    fn description(&self) -> &'static str {
        "Analyzes chat messages to determine if they contain significant narrative events worth processing. This is a fast triage step to filter out mundane conversation."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "messages": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "role": {"type": "string"},
                            "content": {"type": "string"}
                        }
                    },
                    "description": "Recent chat messages to analyze"
                }
            },
            "required": ["messages"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing analyze_text_significance tool");

        let messages = params.get("messages")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ToolError::InvalidParams("messages array is required".to_string()))?;

        // Convert messages to text
        let mut conversation_text = String::new();
        for message in messages {
            if let (Some(role), Some(content)) = (
                message.get("role").and_then(|v| v.as_str()),
                message.get("content").and_then(|v| v.as_str()),
            ) {
                conversation_text.push_str(&format!("\n{}: {}\n", role, content));
            }
        }

        if conversation_text.trim().is_empty() {
            return Ok(json!({
                "is_significant": false,
                "confidence": 1.0,
                "reason": "No content to analyze",
                "suggested_categories": []
            }));
        }

        // Create the triage prompt
        let prompt = format!(
            r#"Analyze this roleplay conversation and determine if it contains narratively significant events that should be recorded.

CONVERSATION:
{}

Consider significant:
- Character deaths, injuries, or major changes
- Discovery of new locations, items, or lore  
- Combat or conflict with consequences
- Major plot developments or revelations
- Changes to relationships or world state

Consider NOT significant:
- Regular conversation or dialogue
- Movement without discovery
- Routine actions without consequences
- Minor character interactions

Respond with JSON:
{{
    "is_significant": boolean,
    "confidence": float,
    "reason": "string explanation",
    "suggested_categories": ["array of strings like chronicle_events, lorebook_entries"]
}}"#,
            conversation_text
        );

        // Call AI for analysis
        match self.call_ai_for_triage(&prompt).await {
            Ok(result) => Ok(result),
            Err(e) => {
                error!("AI triage analysis failed: {}", e);
                // Fallback to conservative analysis
                Ok(json!({
                    "is_significant": false,
                    "confidence": 0.1,
                    "reason": format!("AI analysis failed: {}", e),
                    "suggested_categories": []
                }))
            }
        }
    }
}

impl AnalyzeTextSignificanceTool {
    /// Helper method to call AI for triage analysis
    async fn call_ai_for_triage(&self, prompt: &str) -> Result<ToolResult, ToolError> {
        use genai::chat::{
            ChatOptions as GenAiChatOptions, HarmBlockThreshold, HarmCategory, SafetySetting,
            ChatRole, MessageContent, ChatMessage as GenAiChatMessage
        };
        
        let user_message = GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text(prompt.to_string()),
            options: None,
        };

        let mut genai_chat_options = GenAiChatOptions::default();
        genai_chat_options = genai_chat_options.with_temperature(0.2); // Low temp for consistent triage
        genai_chat_options = genai_chat_options.with_max_tokens(1024);
        
        // Add safety settings
        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];
        genai_chat_options = genai_chat_options.with_safety_settings(safety_settings);

        let system_prompt = "You are a narrative triage agent. Analyze roleplay conversations and determine if they contain significant events worth recording. Respond only with valid JSON.";
        let chat_req = genai::chat::ChatRequest::new(vec![user_message]).with_system(system_prompt);
        
        let response = self.ai_client
            .exec_chat("gemini-2.5-flash-lite-preview-06-17", chat_req, Some(genai_chat_options))
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("AI call failed: {}", e)))?;

        let content = response.first_content_text_as_str().unwrap_or_default();
        
        // Parse JSON response
        let cleaned_content = if content.trim().starts_with("```json") {
            let start = content.find("```json").unwrap() + 7;
            let end = content.rfind("```").unwrap_or(content.len());
            content[start..end].trim()
        } else if content.trim().starts_with("```") {
            let start = content.find("```").unwrap() + 3;
            let end = content.rfind("```").unwrap_or(content.len());
            content[start..end].trim()
        } else {
            content.trim()
        };

        serde_json::from_str(cleaned_content)
            .map_err(|e| ToolError::ExecutionFailed(format!("JSON parse failed: {}", e)))
    }
}

/// Tool for extracting temporal events from text (no DB operations)
pub struct ExtractTemporalEventsTool {
    ai_client: Arc<dyn AiClient>,
}

impl ExtractTemporalEventsTool {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self { ai_client }
    }
}

#[async_trait]
impl ScribeTool for ExtractTemporalEventsTool {
    fn name(&self) -> &'static str {
        "extract_temporal_events"
    }

    fn description(&self) -> &'static str {
        "Extracts discrete temporal events from chat messages without saving to database. Returns structured event data that can be used with create_chronicle_event tool. Use this to identify events that happened at specific times."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "messages": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "role": {"type": "string"},
                            "content": {"type": "string"}
                        }
                    },
                    "description": "Chat messages to extract events from"
                }
            },
            "required": ["messages"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing extract_temporal_events tool");

        let _messages = params.get("messages")
            .ok_or_else(|| ToolError::InvalidParams("messages is required".to_string()))?;

        // For now, return mock extracted events
        // In a real implementation, this would use AI to extract events
        Ok(json!({
            "events": [
                {
                    "event_type": "COMBAT",
                    "summary": "The party defeated a group of goblins",
                    "participants": ["Thorin", "Gandalf", "Bilbo"],
                    "location": "Misty Mountains",
                    "consequences": ["Gained goblin treasure", "Bilbo found the ring"]
                },
                {
                    "event_type": "DISCOVERY",
                    "summary": "Bilbo discovered a mysterious golden ring",
                    "participants": ["Bilbo"],
                    "location": "Goblin caves",
                    "details": "The ring seemed to make him invisible"
                }
            ]
        }))
    }
}

/// Tool for creating a single lorebook entry (atomic operation)
pub struct CreateLorebookEntryTool {
    lorebook_service: Arc<LorebookService>,
}

impl CreateLorebookEntryTool {
    pub fn new(lorebook_service: Arc<LorebookService>) -> Self {
        Self {
            lorebook_service,
        }
    }
}

#[async_trait]
impl ScribeTool for CreateLorebookEntryTool {
    fn name(&self) -> &'static str {
        "create_lorebook_entry"
    }

    fn description(&self) -> &'static str {
        "Creates a single lorebook entry. Use this for recording persistent world-building information that doesn't change over time. Examples: character descriptions, location details, organization structure, magic systems, world lore."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "lorebook_id": {
                    "type": "string",
                    "description": "The UUID of the lorebook to add the entry to"
                },
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user creating the entry"
                },
                "name": {
                    "type": "string",
                    "description": "The name/title of the lorebook entry"
                },
                "content": {
                    "type": "string",
                    "description": "The detailed content of the lorebook entry"
                },
                "keywords": {
                    "type": "string",
                    "description": "Space-separated keywords for the entry"
                },
                "tags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Categories or tags for the entry (e.g., CHARACTER, LOCATION, ORGANIZATION)"
                },
                "enabled": {
                    "type": "boolean",
                    "description": "Whether this entry should be active",
                    "default": true
                }
            },
            "required": ["lorebook_id", "user_id", "name", "content"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing create_lorebook_entry tool with params: {}", params);

        // Extract parameters
        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        // Accept both "name" and "title" for compatibility
        let name = params.get("name")
            .or_else(|| params.get("title"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("name or title is required".to_string()))?;

        let content = params.get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("content is required".to_string()))?;

        let keywords = params.get("keywords")
            .and_then(|v| v.as_str())
            .map(|s| if s.is_empty() { None } else { Some(s.to_string()) })
            .flatten();

        // Parse user UUID
        let user_uuid = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        // Extract session DEK (for encryption)
        let session_dek_bytes = params.get("session_dek")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
            .ok_or_else(|| ToolError::InvalidParams("session_dek is required for lorebook entry creation".to_string()))?;

        // Optional lorebook_id - if not provided, we'll find or create a default one
        let lorebook_id = params.get("lorebook_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        info!(
            "Creating lorebook entry '{}' for user {} with {} characters of content",
            name,
            user_uuid,
            content.len()
        );

        // Use the narrative intelligence lorebook creation method
        match self.lorebook_service.create_entry_for_narrative_intelligence(
            user_uuid,
            lorebook_id,
            name.to_string(),
            content.to_string(),
            keywords,
            &session_dek_bytes,
        ).await {
            Ok(entry_response) => {
                info!("Successfully created lorebook entry: {}", entry_response.id);
                Ok(json!({
                    "success": true,
                    "entry_id": entry_response.id,
                    "lorebook_id": entry_response.lorebook_id,
                    "message": "Lorebook entry created successfully",
                    "title": entry_response.entry_title,
                    "content_length": entry_response.content.len()
                }))
            }
            Err(e) => {
                error!("Failed to create lorebook entry: {}", e);
                Err(ToolError::AppError(e))
            }
        }
    }
}

/// Tool for extracting world-building concepts from text (no DB operations)
pub struct ExtractWorldConceptsTool {
    ai_client: Arc<dyn AiClient>,
}

impl ExtractWorldConceptsTool {
    pub fn new(ai_client: Arc<dyn AiClient>) -> Self {
        Self { ai_client }
    }
}

#[async_trait]
impl ScribeTool for ExtractWorldConceptsTool {
    fn name(&self) -> &'static str {
        "extract_world_concepts"
    }

    fn description(&self) -> &'static str {
        "Extracts persistent world-building concepts from chat messages without saving to database. Returns structured data about characters, locations, organizations, items, and lore that can be used with create_lorebook_entry tool."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "messages": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "role": {"type": "string"},
                            "content": {"type": "string"}
                        }
                    },
                    "description": "Chat messages to extract world concepts from"
                }
            },
            "required": ["messages"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing extract_world_concepts tool");

        let _messages = params.get("messages")
            .ok_or_else(|| ToolError::InvalidParams("messages is required".to_string()))?;

        // For now, return mock extracted concepts
        // In a real implementation, this would use AI to extract world-building info
        Ok(json!({
            "concepts": [
                {
                    "name": "Thorin Oakenshield",
                    "category": "CHARACTER",
                    "content": "A dwarf prince and leader of the Company. Proud, stubborn, but ultimately noble. Wields the sword Orcrist.",
                    "keywords": "thorin dwarf prince oakenshield orcrist",
                    "relationships": ["Bilbo Baggins", "Gandalf", "Company of Thorin"]
                },
                {
                    "name": "The One Ring",
                    "category": "ITEM",
                    "content": "A golden ring of power that grants invisibility to its wearer. Found by Bilbo in the goblin caves.",
                    "keywords": "ring one ring power invisibility precious",
                    "properties": ["Grants invisibility", "Corrupts the bearer", "Sentient"]
                },
                {
                    "name": "Misty Mountains",
                    "category": "LOCATION",
                    "content": "A vast mountain range filled with goblin tunnels and ancient secrets. Home to many dangers.",
                    "keywords": "misty mountains goblin caves",
                    "notable_features": ["Goblin Town", "High Pass", "Ancient tunnels"]
                }
            ]
        }))
    }
}

/// Tool for searching knowledge base using vector embeddings (Step 2 of workflow)
pub struct SearchKnowledgeBaseTool {
    qdrant_service: Arc<dyn QdrantClientServiceTrait>,
    embedding_client: Arc<dyn EmbeddingClient>,
}

impl SearchKnowledgeBaseTool {
    pub fn new(
        qdrant_service: Arc<dyn QdrantClientServiceTrait>,
        embedding_client: Arc<dyn EmbeddingClient>,
    ) -> Self {
        Self {
            qdrant_service,
            embedding_client,
        }
    }
}

#[async_trait]
impl ScribeTool for SearchKnowledgeBaseTool {
    fn name(&self) -> &'static str {
        "search_knowledge_base"
    }

    fn description(&self) -> &'static str {
        "Searches across existing chronicles and lorebook entries to find relevant information. Use this before creating new entries to avoid duplication and to understand existing context."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The search query (e.g., character name, location, concept)"
                },
                "search_type": {
                    "type": "string",
                    "enum": ["all", "chronicles", "lorebooks"],
                    "description": "What to search: 'all' for both, 'chronicles' for events only, 'lorebooks' for lore only",
                    "default": "all"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return",
                    "default": 10,
                    "minimum": 1,
                    "maximum": 50
                }
            },
            "required": ["query"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing search_knowledge_base tool with params: {}", params);

        let query = params.get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("query is required".to_string()))?;

        let search_type = params.get("search_type")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        let limit = params.get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(10);

        info!("Vector searching knowledge base for '{}' (type: {}, limit: {})", query, search_type, limit);

        // Use the existing embeddings infrastructure for vector search
        let query_embedding = match self.embedding_client
            .embed_content(query, "RETRIEVAL_QUERY", None)
            .await 
        {
            Ok(embedding) => embedding,
            Err(e) => {
                error!("Failed to generate query embedding: {}", e);
                return Err(ToolError::ExecutionFailed(format!("Embedding generation failed: {}", e)));
            }
        };

        // Perform vector search using Qdrant
        let search_results = match self.qdrant_service
            .search_points(
                query_embedding,
                limit,
                None, // no additional filters for now - search across all content types
            )
            .await
        {
            Ok(search_results) => search_results,
            Err(e) => {
                error!("Vector search failed: {}", e);
                return Err(ToolError::ExecutionFailed(format!("Vector search failed: {}", e)));
            }
        };

        // Convert search results to our format and filter by search_type
        let mut results = Vec::new();
        for scored_point in search_results {
            let payload_map = scored_point.payload.clone();
            
            // Try to parse as different metadata types
            if let Ok(lorebook_meta) = LorebookChunkMetadata::try_from(payload_map.clone()) {
                let should_include = matches!(search_type, "all" | "lorebooks");
                if should_include {
                    results.push(json!({
                        "type": "lorebook_entry",
                        "id": lorebook_meta.original_lorebook_entry_id,
                        "title": lorebook_meta.entry_title.clone().unwrap_or_else(|| "Untitled".to_string()),
                        "content": lorebook_meta.chunk_text.clone(),
                        "relevance_score": scored_point.score,
                        "snippet": lorebook_meta.chunk_text.chars().take(200).collect::<String>(),
                        "keywords": lorebook_meta.keywords
                    }));
                }
            } else if let Ok(chat_meta) = ChatMessageChunkMetadata::try_from(payload_map.clone()) {
                let should_include = matches!(search_type, "all");
                if should_include {
                    results.push(json!({
                        "type": "chat_message",
                        "id": chat_meta.message_id,
                        "title": format!("Chat from {}", chat_meta.session_id),
                        "content": chat_meta.text.clone(),
                        "relevance_score": scored_point.score,
                        "snippet": chat_meta.text.chars().take(200).collect::<String>(),
                        "speaker": chat_meta.speaker
                    }));
                }
            } else if let Ok(chronicle_meta) = ChronicleEventMetadata::try_from(payload_map.clone()) {
                let should_include = matches!(search_type, "all" | "chronicles");
                if should_include {
                    results.push(json!({
                        "type": "chronicle_event", 
                        "id": chronicle_meta.event_id,
                        "title": format!("Chronicle Event: {}", chronicle_meta.event_type),
                        "content": format!("Event type: {}, Chronicle: {}, Created: {}", 
                                         chronicle_meta.event_type, 
                                         chronicle_meta.chronicle_id,
                                         chronicle_meta.created_at.format("%Y-%m-%d %H:%M:%S")),
                        "relevance_score": scored_point.score,
                        "snippet": format!("Event type: {}", chronicle_meta.event_type),
                        "event_type": chronicle_meta.event_type,
                        "chronicle_id": chronicle_meta.chronicle_id.to_string(),
                        "created_at": chronicle_meta.created_at.to_rfc3339()
                    }));
                }
            } else {
                // Skip unknown payload types with debug info
                warn!(
                    point_id = %scored_point.id.as_ref().map(|id| format!("{id:?}")).unwrap_or_default(),
                    "Failed to parse payload as any known metadata type"
                );
            }
        }

        Ok(json!({
            "success": true,
            "query": query,
            "total_results": results.len(),
            "results": results,
            "search_method": "vector_embeddings"
        }))
    }
}

/// Tool for updating existing lorebook entries
pub struct UpdateLorebookEntryTool {
    lorebook_service: Arc<LorebookService>,
    app_state: Arc<AppState>,
}

impl UpdateLorebookEntryTool {
    pub fn new(lorebook_service: Arc<LorebookService>, app_state: Arc<AppState>) -> Self {
        Self {
            lorebook_service,
            app_state,
        }
    }
}

#[async_trait]
impl ScribeTool for UpdateLorebookEntryTool {
    fn name(&self) -> &'static str {
        "update_lorebook_entry"
    }

    fn description(&self) -> &'static str {
        "Updates an existing lorebook entry with new information. Use this when events change the state of existing world elements (e.g., a city is destroyed, a character dies, an organization changes)."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "entry_id": {
                    "type": "string",
                    "description": "The UUID of the lorebook entry to update"
                },
                "new_content": {
                    "type": "string", 
                    "description": "The updated content for the entry"
                },
                "updated_keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Updated keywords for the entry (optional)"
                },
                "append_mode": {
                    "type": "boolean",
                    "description": "If true, append to existing content instead of replacing it",
                    "default": false
                }
            },
            "required": ["entry_id", "new_content"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing update_lorebook_entry tool with params: {}", params);

        let entry_id = params.get("entry_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("entry_id is required".to_string()))?;

        let new_content = params.get("new_content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("new_content is required".to_string()))?;

        let _updated_keywords = params.get("updated_keywords")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" "));

        let append_mode = params.get("append_mode")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Parse entry_id as UUID
        let entry_uuid = Uuid::parse_str(entry_id)
            .map_err(|_| ToolError::InvalidParams("Invalid entry_id format".to_string()))?;

        info!("Updating lorebook entry {} (append_mode: {})", entry_uuid, append_mode);

        // TODO: Implement the actual update logic
        // This would involve:
        // 1. Fetching the existing entry
        // 2. Updating the content (append or replace)
        // 3. Updating keywords if provided
        // 4. Saving the changes
        
        // For now, return a placeholder response
        Ok(json!({
            "success": true,
            "entry_id": entry_uuid,
            "message": "Lorebook entry update functionality not yet implemented",
            "append_mode": append_mode,
            "content_length": new_content.len()
        }))
    }
}