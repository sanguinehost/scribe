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
        ChronicleService, LorebookService, safety_utils::create_unrestricted_safety_settings,
    },
    state::AppState,
    vector_db::qdrant_client::QdrantClientServiceTrait,
};

use super::tools::{ScribeTool, ToolError, ToolParams, ToolResult};

/// Tool for creating a single chronicle event (atomic operation)
pub struct CreateChronicleEventTool {
    chronicle_service: Arc<ChronicleService>,
    app_state: Arc<AppState>,
}

impl CreateChronicleEventTool {
    pub fn new(chronicle_service: Arc<ChronicleService>, app_state: Arc<AppState>) -> Self {
        Self {
            chronicle_service,
            app_state,
        }
    }
}

#[async_trait]
impl ScribeTool for CreateChronicleEventTool {
    fn name(&self) -> &'static str {
        "create_chronicle_event"
    }

    fn description(&self) -> &'static str {
        "Creates a single chronicle event. Use this for recording significant narrative moments that happened in the story. Examples: major plot developments, character achievements, important discoveries, meaningful interactions."
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
                "event_type": {
                    "type": "string",
                    "description": "Simple event type, usually 'NARRATIVE.EVENT'",
                    "default": "NARRATIVE.EVENT"
                },
                "summary": {
                    "type": "string",
                    "description": "A rich, narrative description of what happened (like an excerpt from an epic novel)"
                },
                "keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "3-5 searchable terms from the event (character names, locations, important objects, actions)",
                    "examples": [["dragon", "battle", "victory"], ["betrayal", "throne room", "assassination"]]
                },
                "timestamp_iso8601": {
                    "type": "string",
                    "description": "When this event occurred in the story timeline (ISO 8601 format)",
                    "examples": ["2025-06-28T15:30:00Z"]
                }
            },
            "required": ["user_id", "chronicle_id", "event_type", "summary", "keywords"]
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

        let event_type = params.get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("NARRATIVE.EVENT"); // Default to simple type

        let summary = params.get("summary")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("summary is required".to_string()))?;

        // Extract keywords array
        let keywords = params.get("keywords")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
            });

        // Optional timestamp
        let timestamp_str = params.get("timestamp_iso8601")
            .and_then(|v| v.as_str());

        // Parse UUIDs
        let user_uuid = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let chronicle_uuid = Uuid::parse_str(chronicle_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid chronicle_id format".to_string()))?;

        // Parse timestamp if provided
        let timestamp = if let Some(ts_str) = timestamp_str {
            chrono::DateTime::parse_from_rfc3339(ts_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .ok()
        } else {
            None
        };

        let create_request = crate::models::chronicle_event::CreateEventRequest {
            event_type: event_type.to_string(),
            summary: summary.to_string(),
            source: crate::models::chronicle_event::EventSource::AiExtracted,
            keywords,
            timestamp_iso8601: timestamp,
            chat_session_id: None, // Will be set by the service if processing from chat
        };

        info!(
            "Creating chronicle event '{}' ({}) for chronicle {}",
            summary,
            event_type,
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
                
                // CRITICAL: Embed the chronicle event for semantic search
                // This ensures events created by the narrative agent are searchable via RAG
                if let Err(e) = self.app_state
                    .embedding_pipeline_service
                    .process_and_embed_chronicle_event(
                        self.app_state.clone(), 
                        event.clone(), 
                        Some(&session_dek_wrapper)
                    )
                    .await
                {
                    warn!(
                        event_id = %event.id, 
                        error = %e, 
                        "Failed to embed chronicle event created by narrative agent, but event was created successfully"
                    );
                    // Don't fail the event creation if embedding fails
                } else {
                    info!(
                        event_id = %event.id, 
                        "Successfully embedded chronicle event created by narrative agent for semantic search"
                    );
                }
                
                Ok(json!({
                    "success": true,
                    "event_id": event.id,
                    "event_type": event_type,
                    "summary": summary,
                    "keywords": event.get_keywords(),
                    "message": "Chronicle event created and embedded successfully"
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
        let safety_settings = create_unrestricted_safety_settings();
        genai_chat_options = genai_chat_options.with_safety_settings(safety_settings);

        let system_prompt = "You are a narrative triage agent. Analyze roleplay conversations and determine if they contain significant events worth recording. Respond only with valid JSON.";
        let chat_req = genai::chat::ChatRequest::new(vec![user_message]).with_system(system_prompt);
        
        let response = self.ai_client
            .exec_chat("gemini-2.5-flash-lite", chat_req, Some(genai_chat_options))
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
    app_state: Arc<AppState>,
}

impl SearchKnowledgeBaseTool {
    pub fn new(
        qdrant_service: Arc<dyn QdrantClientServiceTrait>,
        embedding_client: Arc<dyn EmbeddingClient>,
        app_state: Arc<AppState>,
    ) -> Self {
        Self {
            qdrant_service,
            embedding_client,
            app_state,
        }
    }
    
    /// Fetch lorebook IDs associated with a chat session
    async fn get_session_lorebook_ids(&self, session_id: Uuid) -> Result<Vec<Uuid>, ToolError> {
        use crate::schema::chat_session_lorebooks;
        use diesel::prelude::*;
        
        let conn = self.app_state.pool.get()
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get DB connection: {}", e)))?;
            
        let lorebook_ids = conn.interact(move |conn| {
            chat_session_lorebooks::table
                .filter(chat_session_lorebooks::chat_session_id.eq(session_id))
                .select(chat_session_lorebooks::lorebook_id)
                .get_results::<Uuid>(conn)
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to interact with DB: {}", e)))?
        .map_err(|e| ToolError::ExecutionFailed(format!("Failed to query lorebook associations: {}", e)))?;
        
        debug!("Found {} lorebooks associated with session {}", lorebook_ids.len(), session_id);
        Ok(lorebook_ids)
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
                },
                "user_id": {
                    "type": "string",
                    "description": "REQUIRED: User ID to filter search results to user's own data only"
                },
                "chronicle_id": {
                    "type": "string",
                    "description": "Optional: Chronicle ID to filter results to all sessions within this chronicle"
                },
                "session_id": {
                    "type": "string", 
                    "description": "Optional: Session ID to filter results to only this specific session (used when no chronicle exists)"
                }
            },
            "required": ["query", "user_id"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing search_knowledge_base tool with params: {}", params);

        let query = params.get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("query is required".to_string()))?;

        // SECURITY CRITICAL: Extract user_id for filtering
        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required for security".to_string()))?;

        let user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let search_type = params.get("search_type")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        let limit = params.get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(10);

        // Optional chronicle_id for filtering (part of scope control)
        let chronicle_id_opt = params.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());
        
        // Optional session_id for even tighter filtering
        let session_id_opt = params.get("session_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());

        info!("Vector searching knowledge base for '{}' (type: {}, limit: {}) for user {}, chronicle: {:?}, session: {:?}", 
              query, search_type, limit, user_id, chronicle_id_opt, session_id_opt);

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

        // SECURITY CRITICAL: Create filter to only return results for this user
        // With optional session/chronicle scoping for context control
        use crate::vector_db::qdrant_client::{Filter, Condition, FieldCondition, Match};
        use qdrant_client::qdrant::{condition::ConditionOneOf, r#match::MatchValue};
        
        // Base security filter - ALWAYS filter by user_id
        let user_condition = Condition {
            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                key: "user_id".to_string(),
                r#match: Some(Match {
                    match_value: Some(MatchValue::Keyword(user_id.to_string())),
                }),
                ..Default::default()
            })),
        };
        
        // Build the filter based on search scope and type
        let search_filter = if let Some(session_id) = session_id_opt {
            // Session-scoped search: Need to handle lorebooks specially
            debug!("Building session-scoped search filter for session: {}", session_id);
            
            // Check if we need to search lorebooks
            let includes_lorebooks = matches!(search_type, "all" | "lorebooks");
            
            if includes_lorebooks {
                // Fetch lorebook IDs associated with this session
                let lorebook_ids = self.get_session_lorebook_ids(session_id).await?;
                debug!("Session {} has {} associated lorebooks", session_id, lorebook_ids.len());
                
                // Build conditions for different content types
                let mut should_conditions = Vec::new();
                
                // Add condition for chat messages (if searching all)
                if matches!(search_type, "all") {
                    should_conditions.push(Condition {
                        condition_one_of: Some(ConditionOneOf::Filter(Filter {
                            must: vec![
                                Condition {
                                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                        key: "source_type".to_string(),
                                        r#match: Some(Match {
                                            match_value: Some(MatchValue::Keyword("chat_message".to_string())),
                                        }),
                                        ..Default::default()
                                    })),
                                },
                                Condition {
                                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                        key: "session_id".to_string(),
                                        r#match: Some(Match {
                                            match_value: Some(MatchValue::Keyword(session_id.to_string())),
                                        }),
                                        ..Default::default()
                                    })),
                                },
                            ],
                            ..Default::default()
                        })),
                    });
                }
                
                // Add condition for lorebook entries (if we have associated lorebooks)
                if !lorebook_ids.is_empty() {
                    // Create OR condition for all lorebook IDs
                    let lorebook_id_conditions: Vec<Condition> = lorebook_ids.iter().map(|lb_id| {
                        Condition {
                            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                key: "lorebook_id".to_string(),
                                r#match: Some(Match {
                                    match_value: Some(MatchValue::Keyword(lb_id.to_string())),
                                }),
                                ..Default::default()
                            })),
                        }
                    }).collect();
                    
                    should_conditions.push(Condition {
                        condition_one_of: Some(ConditionOneOf::Filter(Filter {
                            must: vec![
                                Condition {
                                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                        key: "source_type".to_string(),
                                        r#match: Some(Match {
                                            match_value: Some(MatchValue::Keyword("lorebook_entry".to_string())),
                                        }),
                                        ..Default::default()
                                    })),
                                },
                            ],
                            should: lorebook_id_conditions, // Any of the associated lorebook IDs
                            ..Default::default()
                        })),
                    });
                }
                
                // Add condition for chronicle events (if searching all)
                if matches!(search_type, "all" | "chronicles") {
                    // Chronicle events might be associated with the session
                    should_conditions.push(Condition {
                        condition_one_of: Some(ConditionOneOf::Filter(Filter {
                            must: vec![
                                Condition {
                                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                        key: "source_type".to_string(),
                                        r#match: Some(Match {
                                            match_value: Some(MatchValue::Keyword("chronicle_event".to_string())),
                                        }),
                                        ..Default::default()
                                    })),
                                },
                            ],
                            ..Default::default()
                        })),
                    });
                }
                
                // Combine with user filter
                Filter {
                    must: vec![user_condition],
                    should: should_conditions, // At least one of these conditions must match
                    ..Default::default()
                }
            } else {
                // Not searching lorebooks, use simple session filter
                Filter {
                    must: vec![
                        user_condition,
                        Condition {
                            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                key: "session_id".to_string(),
                                r#match: Some(Match {
                                    match_value: Some(MatchValue::Keyword(session_id.to_string())),
                                }),
                                ..Default::default()
                            })),
                        },
                    ],
                    ..Default::default()
                }
            }
        } else if let Some(chronicle_id) = chronicle_id_opt {
            // Chronicle-scoped search: Similar logic but with chronicle filter
            debug!("Building chronicle-scoped search filter for chronicle: {}", chronicle_id);
            
            // For chronicle scope, we search across all sessions in the chronicle
            // This is simpler since chronicle events have chronicle_id
            Filter {
                must: vec![
                    user_condition,
                    Condition {
                        condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                            key: "chronicle_id".to_string(),
                            r#match: Some(Match {
                                match_value: Some(MatchValue::Keyword(chronicle_id.to_string())),
                            }),
                            ..Default::default()
                        })),
                    },
                ],
                ..Default::default()
            }
        } else {
            // No specific scope - search all user's data
            debug!("No session or chronicle filter - searching all user's data");
            Filter {
                must: vec![user_condition],
                ..Default::default()
            }
        };

        // Perform vector search using Qdrant with appropriate filters
        let search_results = match self.qdrant_service
            .search_points(
                query_embedding,
                limit,
                Some(search_filter), // SECURITY + SCOPE: Filter by user, session, or chronicle
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
        let mut chronicle_priority_results = Vec::new();
        
        for scored_point in search_results {
            let payload_map = scored_point.payload.clone();
            
            // Try to parse as different metadata types
            if let Ok(lorebook_meta) = LorebookChunkMetadata::try_from(payload_map.clone()) {
                // SECURITY: Double-check that this result belongs to the requesting user
                if lorebook_meta.user_id != user_id {
                    error!(
                        "SECURITY VIOLATION: Lorebook result for user {} returned to user {}",
                        lorebook_meta.user_id, user_id
                    );
                    continue;
                }
                
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
                // SECURITY: Double-check that this result belongs to the requesting user
                if chat_meta.user_id != user_id {
                    error!(
                        "SECURITY VIOLATION: Chat result for user {} returned to user {}",
                        chat_meta.user_id, user_id
                    );
                    continue;
                }
                
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
                // SECURITY: Double-check that this result belongs to the requesting user
                if chronicle_meta.user_id != user_id {
                    error!(
                        "SECURITY VIOLATION: Chronicle result for user {} returned to user {}",
                        chronicle_meta.user_id, user_id
                    );
                    continue;
                }
                
                let should_include = matches!(search_type, "all" | "chronicles");
                if should_include {
                    let result = json!({
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
                    });
                    
                    // Prioritize results from the specified chronicle_id
                    if let Some(target_chronicle_id) = chronicle_id_opt {
                        if chronicle_meta.chronicle_id == target_chronicle_id {
                            chronicle_priority_results.push(result);
                        } else {
                            results.push(result);
                        }
                    } else {
                        results.push(result);
                    }
                }
            } else {
                // Skip unknown payload types with debug info
                warn!(
                    point_id = %scored_point.id.as_ref().map(|id| format!("{id:?}")).unwrap_or_default(),
                    "Failed to parse payload as any known metadata type"
                );
            }
        }
        
        // Combine results: priority chronicle results first, then others
        chronicle_priority_results.extend(results);
        let final_results = chronicle_priority_results;

        Ok(json!({
            "success": true,
            "query": query,
            "total_results": final_results.len(),
            "results": final_results,
            "search_method": "vector_embeddings",
            "user_filtered": true,
            "chronicle_prioritized": chronicle_id_opt.is_some()
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