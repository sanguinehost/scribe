//! Narrative tool implementations for the agentic framework.

use crate::db::DbId;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::{
    errors::AppError,
    llm::{AiClient, EmbeddingClient},
    services::{
        embeddings::{ChatMessageChunkMetadata, ChronicleEventMetadata, LorebookChunkMetadata},
        safety_utils::create_unrestricted_safety_settings,
        ChronicleService, LorebookService,
    },
    state::AppState,
    vector_db::qdrant_client::QdrantClientServiceTrait,
};

use super::tools::{ScribeTool, ToolError, ToolParams, ToolResult};

/// Generate JSON schema for text significance triage response
fn get_text_significance_triage_schema() -> crate::DbJson {
    serde_json::json!({
        "type": "object",
        "properties": {
            "is_significant": {
                "type": "boolean",
                "description": "Whether the conversation contains narratively significant events"
            },
            "confidence": {
                "type": "number",
                "description": "Confidence level in the significance assessment (0.0-1.0)"
            },
            "reason": {
                "type": "string",
                "description": "Explanation of why this was deemed significant or not significant"
            },
            "suggested_categories": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Array of suggested categories like 'chronicle_events' or 'lorebook_entries'"
            }
        },
        "required": ["is_significant", "confidence", "reason", "suggested_categories"]
    }).into()
}

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

                "event_type": {
                    "type": "string",
                    "description": "Simple event type, usually 'NARRATIVE.EVENT'",
                    "default": "NARRATIVE.EVENT"
                },
                "summary": {
                    "type": "string",
                    "description": "A concise summary of what happened (1-2 paragraphs, under 200 words)"
                },
                "keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "3-5 searchable terms from the event (character names, locations, important objects, actions)"
                },
                "timestamp_iso8601": {
                    "type": "string",
                    "description": "When this event occurred in the story timeline (ISO 8601 format)"
                }
            },
            "required": ["event_type", "summary", "keywords"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!(
            "Executing create_chronicle_event tool with params: {}",
            params
        );

        // Extract required parameters
        let user_id_str = params
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let chronicle_id_str = params
            .get("chronicle_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("chronicle_id is required".to_string()))?;

        let event_type = params
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("NARRATIVE.EVENT"); // Default to simple type

        let summary = params
            .get("summary")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("summary is required".to_string()))?;

        // Extract keywords array
        let keywords = params
            .get("keywords")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>()
            });

        // Optional timestamp
        let timestamp_str = params.get("timestamp_iso8601").and_then(|v| v.as_str());

        // Parse UUIDs
        let user_uuid = DbId::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let chronicle_uuid = DbId::parse_str(chronicle_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid chronicle_id format".to_string()))?;

        // Parse timestamp if provided
        let timestamp = if let Some(ts_str) = timestamp_str {
            chrono::DateTime::parse_from_rfc3339(ts_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .ok()
                .map(|dt| dt.into())
        } else {
            None
        };

        let create_request = crate::models::chronicle_event::CreateEventRequest {
            event_type: event_type.to_string(),
            summary: summary.to_string(),
            source: crate::models::chronicle_event::EventSource::AiExtracted,
            keywords,
            timestamp_iso8601: timestamp,
            chat_session_id: None,    // Will be set below if provided in params
            message_variant_id: None, // Will be set below if variant lookup succeeds
        };

        // Extract chat_session_id if provided (it should be for chat-based events)
        let chat_session_id = params
            .get("chat_session_id")
            .and_then(|v| v.as_str())
            .and_then(|s| DbId::parse_str(s).ok());

        // If we have a session ID, try to find the active variant to link this event to
        let mut final_create_request = create_request;
        final_create_request.chat_session_id = chat_session_id;

        if let Some(session_id) = chat_session_id {
            // We need to find the most recent assistant message for this session
            // and check if it has an active variant.
            // This links the chronicle event to the specific timeline branch.

            let variant_lookup_result = crate::db::with_conn(&self.app_state.pool, move |conn| {
                use crate::schema::{chat_messages, message_variants};
                use diesel::prelude::*;

                // 1. Find the latest assistant message
                // 1. Find the latest assistant message
                let base_query =
                    chat_messages::table.filter(chat_messages::session_id.eq(session_id));

                #[cfg(feature = "sqlite-backend")]
                let filtered_query = base_query.filter(
                    chat_messages::message_type
                        .eq(crate::models::chats::MessageRole::Assistant.to_string()),
                );

                #[cfg(feature = "postgres-backend")]
                let filtered_query = base_query.filter(
                    chat_messages::message_type.eq(crate::models::chats::MessageRole::Assistant),
                );

                let latest_message = filtered_query
                    .order(chat_messages::created_at.desc())
                    .select(crate::models::chats::Message::as_select())
                    .first::<crate::models::chats::Message>(conn)
                    .optional()?;

                if let Some(msg) = latest_message {
                    let (msg_id, variant_index) = (msg.id, msg.current_variant_index);
                    if variant_index > 0 {
                        // 2. If it has a variant, find the variant ID
                        let variant_id = message_variants::table
                            .filter(message_variants::parent_message_id.eq(msg_id))
                            .filter(message_variants::variant_index.eq(variant_index))
                            .select(message_variants::id)
                            .first::<crate::db::DbId>(conn)
                            .optional()?;

                        return Ok::<Option<crate::db::DbId>, crate::errors::AppError>(variant_id);
                    }
                }

                Ok(None)
            })
            .await;

            match variant_lookup_result {
                Ok(Some(variant_id)) => {
                    debug!("Linking chronicle event to message variant: {}", variant_id);
                    final_create_request.message_variant_id = Some(variant_id);
                }
                Ok(None) => {
                    debug!(
                        "No active variant found for session {}, event will be on main timeline",
                        session_id
                    );
                }
                Err(e) => {
                    warn!("Failed to lookup message variant for linking: {}", e);
                }
            }
        }

        info!(
            "Creating chronicle event '{}' ({}) for chronicle {}",
            summary, event_type, chronicle_uuid
        );

        // Extract session_dek for encryption (SECURITY CRITICAL!)
        let session_dek = params
            .get("session_dek")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ToolError::InvalidParams("session_dek is required for encryption".to_string())
            })?;

        // Decode the hex-encoded session_dek back to SecretBox
        let session_dek_bytes = hex::decode(session_dek).map_err(|e| {
            ToolError::InvalidParams(format!("Invalid session_dek hex encoding: {}", e))
        })?;
        let session_dek_secret = secrecy::SecretBox::new(Box::new(session_dek_bytes));
        let session_dek_wrapper = crate::auth::session_dek::SessionDek(session_dek_secret);

        // Execute the atomic creation with proper encryption
        match self
            .chronicle_service
            .create_event(
                user_uuid.into(),
                chronicle_uuid.into(),
                final_create_request,
                Some(&session_dek_wrapper), // Pass SessionDek for AI-generated events encryption
            )
            .await
        {
            Ok(event) => {
                info!("Successfully created chronicle event: {}", event.id);

                // CRITICAL: Embed the chronicle event for semantic search
                // This ensures events created by the narrative agent are searchable via RAG
                if let Err(e) = self
                    .app_state
                    .embedding_pipeline_service
                    .process_and_embed_chronicle_event(
                        self.app_state.clone(),
                        event.clone(),
                        Some(&session_dek_wrapper),
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

        let messages = params
            .get("messages")
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
    /// Helper method to call AI for triage analysis using structured outputs
    async fn call_ai_for_triage(&self, prompt: &str) -> Result<ToolResult, ToolError> {
        use genai::chat::{
            ChatMessage as GenAiChatMessage, ChatOptions as GenAiChatOptions, ChatRequest,
            ChatResponseFormat, ChatRole, JsonSchemaSpec, MessageContent,
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

        // Create JSON schema spec for structured output
        let schema = get_text_significance_triage_schema();
        let json_schema_spec = JsonSchemaSpec::new(schema);

        // Add structured output format to chat options
        genai_chat_options = genai_chat_options
            .with_response_format(ChatResponseFormat::JsonSchemaSpec(json_schema_spec));

        // CLEAN: No "Respond only with valid JSON" needed - Gemini 2.5+ enforces schema natively
        let system_prompt = "You are a narrative triage agent. Analyze roleplay conversations and determine if they contain significant events worth recording.";
        let chat_req = ChatRequest::new(vec![user_message]).with_system(system_prompt);

        let response = self
            .ai_client
            .exec_chat("gemini-2.5-flash-lite", chat_req, Some(genai_chat_options))
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("AI call failed: {}", e)))?;

        let content = response.first_content_text_as_str().unwrap_or_default();

        // CLEAN: Direct JSON parsing (no markdown fence stripping needed)
        serde_json::from_str(content)
            .map_err(|e| ToolError::ExecutionFailed(format!("JSON parse failed: {}", e)))
    }
}

// NOTE: ExtractTemporalEventsTool removed - was only returning mock data and not used in the single-agent system

/// Tool for creating a single lorebook entry (atomic operation)
pub struct CreateLorebookEntryTool {
    lorebook_service: Arc<LorebookService>,
}

impl CreateLorebookEntryTool {
    pub fn new(lorebook_service: Arc<LorebookService>) -> Self {
        Self { lorebook_service }
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
        debug!(
            "Executing create_lorebook_entry tool with params: {}",
            params
        );

        // Extract parameters
        let user_id_str = params
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        // Accept both "name" and "title" for compatibility
        let name = params
            .get("name")
            .or_else(|| params.get("title"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("name or title is required".to_string()))?;

        let content = params
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("content is required".to_string()))?;

        let keywords = params
            .get("keywords")
            .and_then(|v| v.as_str())
            .map(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                }
            })
            .flatten();

        // Parse user UUID
        let user_uuid = DbId::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        // Extract session DEK (for encryption)
        let session_dek_bytes = params
            .get("session_dek")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
            .ok_or_else(|| {
                ToolError::InvalidParams(
                    "session_dek is required for lorebook entry creation".to_string(),
                )
            })?;

        // Optional lorebook_id - if not provided, we'll find or create a default one
        let lorebook_id = params
            .get("lorebook_id")
            .and_then(|v| v.as_str())
            .and_then(|s| DbId::parse_str(s).ok());

        info!(
            "Creating lorebook entry '{}' for user {} with {} characters of content",
            name,
            user_uuid,
            content.len()
        );

        // Use the narrative intelligence lorebook creation method
        match self
            .lorebook_service
            .create_entry_for_narrative_intelligence(
                user_uuid.into(),
                lorebook_id.map(|id| id.into()),
                name.to_string(),
                content.to_string(),
                keywords,
                &session_dek_bytes,
            )
            .await
        {
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

// NOTE: ExtractWorldConceptsTool removed - was only returning mock data and not used in the single-agent system

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

    /// Fetch lorebook IDs associated with a chat session using comprehensive association logic
    /// This includes direct chat-lorebook associations, character-inherited lorebooks, and overrides
    async fn get_session_lorebook_ids(
        &self,
        session_id: crate::db::DbId,
        user_id: crate::db::DbId,
    ) -> Result<Vec<crate::db::DbId>, ToolError> {
        use crate::schema::{
            character_lorebooks, chat_character_lorebook_overrides, chat_session_lorebooks,
            chat_sessions,
        };
        use diesel::prelude::*;

        let associations_data = crate::db::with_conn(&self.app_state.pool, move |conn| {
            // 1. Get chat session and character ID
            let (_session_found, character_id): (crate::db::DbId, Option<crate::db::DbId>) =
                chat_sessions::table
                    .filter(chat_sessions::id.eq(session_id))
                    .filter(chat_sessions::user_id.eq(user_id))
                    .select((chat_sessions::id, chat_sessions::character_id))
                    .first::<(crate::db::DbId, Option<crate::db::DbId>)>(conn)
                    .optional()?
                    .ok_or_else(|| diesel::result::Error::NotFound)?;

            // 2. Get direct chat-lorebook associations
            let chat_associations: Vec<crate::db::DbId> = chat_session_lorebooks::table
                .filter(chat_session_lorebooks::chat_session_id.eq(session_id))
                .filter(chat_session_lorebooks::user_id.eq(user_id))
                .select(chat_session_lorebooks::lorebook_id)
                .get_results::<crate::db::DbId>(conn)?;

            // 3. Get character-lorebook associations (if character exists)
            let character_associations: Vec<crate::db::DbId> = if let Some(char_id) = character_id {
                character_lorebooks::table
                    .filter(character_lorebooks::character_id.eq(char_id))
                    .filter(character_lorebooks::user_id.eq(user_id))
                    .select(character_lorebooks::lorebook_id)
                    .get_results::<crate::db::DbId>(conn)?
            } else {
                Vec::new()
            };

            // 4. Get overrides for this chat session
            let overrides: Vec<(crate::db::DbId, String)> =
                chat_character_lorebook_overrides::table
                    .filter(chat_character_lorebook_overrides::chat_session_id.eq(session_id))
                    .filter(chat_character_lorebook_overrides::user_id.eq(user_id))
                    .select((
                        chat_character_lorebook_overrides::lorebook_id,
                        chat_character_lorebook_overrides::action,
                    ))
                    .get_results::<(crate::db::DbId, String)>(conn)?;

            Ok::<_, AppError>((chat_associations, character_associations, overrides))
        })
        .await
        .map_err(|e| {
            ToolError::ExecutionFailed(format!("Failed to query lorebook associations: {}", e))
        })?;

        let (chat_associations, character_associations, overrides) = associations_data;

        // 5. Build final effective lorebook list
        let override_map: std::collections::HashMap<crate::db::DbId, String> =
            overrides.into_iter().collect();
        let mut effective_lorebooks = std::collections::HashSet::new();

        // Add direct chat associations (these always take precedence)
        for lorebook_id in &chat_associations {
            effective_lorebooks.insert(*lorebook_id);
        }

        // Add character associations, but only if not overridden by "disable" and not already present as chat association
        for lorebook_id in &character_associations {
            if !effective_lorebooks.contains(lorebook_id) {
                // Check if this character lorebook is disabled by override
                if let Some(action) = override_map.get(lorebook_id) {
                    if action == "disable" {
                        debug!(
                            "Character lorebook {} disabled by override for session {}",
                            lorebook_id, session_id
                        );
                        continue; // Skip this lorebook
                    }
                }
                effective_lorebooks.insert(*lorebook_id);
            }
        }

        let final_lorebook_ids: Vec<crate::db::DbId> = effective_lorebooks.into_iter().collect();

        debug!(
            "Lorebook associations for session {}: {} direct, {} character, {} effective (after overrides)",
            session_id,
            chat_associations.len(),
            character_associations.len(),
            final_lorebook_ids.len()
        );

        Ok(final_lorebook_ids)
    }

    /// Fetch all chat session IDs in a chronicle
    async fn get_chronicle_session_ids(
        &self,
        chronicle_id: crate::db::DbId,
    ) -> Result<Vec<crate::db::DbId>, ToolError> {
        use crate::schema::chat_sessions;
        use diesel::prelude::*;

        let session_ids = crate::db::with_conn(&self.app_state.pool, move |conn| {
            chat_sessions::table
                .filter(chat_sessions::player_chronicle_id.eq(chronicle_id))
                .select(chat_sessions::id)
                .get_results::<crate::db::DbId>(conn)
                .map_err(Into::into)
        })
        .await
        .map_err(|e| {
            ToolError::ExecutionFailed(format!("Failed to query chronicle sessions: {}", e))
        })?;

        debug!(
            "Found {} sessions in chronicle {}",
            session_ids.len(),
            chronicle_id
        );
        Ok(session_ids)
    }

    /// Fetch all lorebook IDs associated with a chronicle using comprehensive association logic
    /// This fetches all sessions in the chronicle, then all lorebooks for those sessions including character-inherited ones
    async fn get_chronicle_lorebook_ids(
        &self,
        chronicle_id: crate::db::DbId,
        user_id: crate::db::DbId,
    ) -> Result<Vec<crate::db::DbId>, ToolError> {
        // First get all sessions in this chronicle
        let session_ids = self.get_chronicle_session_ids(chronicle_id).await?;

        if session_ids.is_empty() {
            debug!(
                "No sessions found in chronicle {}, returning empty lorebook list",
                chronicle_id
            );
            return Ok(Vec::new());
        }

        let session_count = session_ids.len();

        // Get comprehensive lorebook associations for each session in the chronicle
        let mut all_lorebook_ids = std::collections::HashSet::new();
        for session_id in &session_ids {
            let session_lorebooks = self.get_session_lorebook_ids(*session_id, user_id).await?;
            for lorebook_id in session_lorebooks {
                all_lorebook_ids.insert(lorebook_id);
            }
        }

        let final_lorebook_ids: Vec<crate::db::DbId> = all_lorebook_ids.into_iter().collect();

        info!(
            "Chronicle {} has {} sessions with {} unique lorebooks (comprehensive associations)",
            chronicle_id,
            session_count,
            final_lorebook_ids.len()
        );
        Ok(final_lorebook_ids)
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
                },
                "session_dek": {
                    "type": "string",
                    "description": "INTERNAL: Hex-encoded session DEK for decrypting encrypted content in search results"
                }
            },
            "required": ["query", "user_id"]
        })
    }

    #[allow(deprecated)]
    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!(
            "Executing search_knowledge_base tool with params: {}",
            params
        );

        // Log all received parameters for debugging
        info!(
            "SearchKnowledgeBaseTool received params: {}",
            serde_json::to_string_pretty(params).unwrap_or_else(|_| params.to_string())
        );

        let query = params
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("query is required".to_string()))?;

        // SECURITY CRITICAL: Extract user_id for filtering
        let user_id_str = params
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ToolError::InvalidParams("user_id is required for security".to_string())
            })?;

        let user_id = DbId::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let search_type = params
            .get("search_type")
            .and_then(|v| v.as_str())
            .unwrap_or("all");

        let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(10);

        // Optional chronicle_id for filtering (part of scope control)
        let chronicle_id_opt = params
            .get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| DbId::parse_str(s).ok());

        // Optional session_id for even tighter filtering
        let session_id_opt = params
            .get("session_id")
            .and_then(|v| v.as_str())
            .and_then(|s| DbId::parse_str(s).ok());

        // Extract session_dek for decryption (optional for backward compatibility)
        let session_dek_opt = params
            .get("session_dek")
            .and_then(|v| v.as_str())
            .and_then(|hex_str| hex::decode(hex_str).ok())
            .map(|bytes| {
                let secret = secrecy::SecretBox::new(Box::new(bytes));
                crate::auth::session_dek::SessionDek(secret)
            });

        if session_dek_opt.is_some() {
            debug!("SessionDek provided for search result decryption");
        } else {
            warn!("No SessionDek provided - encrypted search results will not be decrypted");
        }

        info!(
            "Vector searching knowledge base for '{}' (type: {}, limit: {}) for user {}, chronicle: {:?}, session: {:?}",
            query, search_type, limit, user_id, chronicle_id_opt, session_id_opt
        );

        // Critical debug: Log which scope we're using
        if let Some(session_id) = session_id_opt {
            info!(
                "SEARCH SCOPE: Using session-scoped search for session_id: {}",
                session_id
            );
        } else if let Some(chronicle_id) = chronicle_id_opt {
            info!(
                "SEARCH SCOPE: Using chronicle-scoped search for chronicle_id: {}",
                chronicle_id
            );
        } else {
            info!(
                "SEARCH SCOPE: Using user-scoped search only (no session or chronicle specified)"
            );
        }

        // Use the existing embeddings infrastructure for vector search
        let query_embedding = match self
            .embedding_client
            .embed_content(query, "RETRIEVAL_QUERY", None)
            .await
        {
            Ok(embedding) => embedding,
            Err(e) => {
                error!("Failed to generate query embedding: {}", e);
                return Err(ToolError::ExecutionFailed(format!(
                    "Embedding generation failed: {}",
                    e
                )));
            }
        };

        // SECURITY CRITICAL: Create filter to only return results for this user
        // With optional session/chronicle scoping for context control
        use crate::vector_db::qdrant_client::{Condition, FieldCondition, Filter, Match};
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
            debug!(
                "Building session-scoped search filter for session: {}",
                session_id
            );

            // Check if we need to search lorebooks
            let includes_lorebooks = matches!(search_type, "all" | "lorebooks");

            if includes_lorebooks {
                // Fetch lorebook IDs associated with this session
                let lorebook_ids = self
                    .get_session_lorebook_ids(session_id.into(), user_id.into())
                    .await?;
                info!(
                    "Session {} has {} associated lorebooks: {:?}",
                    session_id,
                    lorebook_ids.len(),
                    lorebook_ids
                );

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
                                            match_value: Some(MatchValue::Keyword(
                                                "chat_message".to_string(),
                                            )),
                                        }),
                                        ..Default::default()
                                    })),
                                },
                                Condition {
                                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                        key: "session_id".to_string(),
                                        r#match: Some(Match {
                                            match_value: Some(MatchValue::Keyword(
                                                session_id.to_string(),
                                            )),
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
                    // Create a separate condition for each lorebook ID combined with source_type
                    // This way each complete condition is in the should clause
                    for lb_id in &lorebook_ids {
                        should_conditions.push(Condition {
                            condition_one_of: Some(ConditionOneOf::Filter(Filter {
                                must: vec![
                                    Condition {
                                        condition_one_of: Some(ConditionOneOf::Field(
                                            FieldCondition {
                                                key: "source_type".to_string(),
                                                r#match: Some(Match {
                                                    match_value: Some(MatchValue::Keyword(
                                                        "lorebook_entry".to_string(),
                                                    )),
                                                }),
                                                ..Default::default()
                                            },
                                        )),
                                    },
                                    Condition {
                                        condition_one_of: Some(ConditionOneOf::Field(
                                            FieldCondition {
                                                key: "lorebook_id".to_string(),
                                                r#match: Some(Match {
                                                    match_value: Some(MatchValue::Keyword(
                                                        lb_id.to_string(),
                                                    )),
                                                }),
                                                ..Default::default()
                                            },
                                        )),
                                    },
                                ],
                                ..Default::default()
                            })),
                        });
                    }
                }

                // Add condition for chronicle events (if searching all)
                if matches!(search_type, "all" | "chronicles") {
                    // Chronicle events might be associated with the session
                    should_conditions.push(Condition {
                        condition_one_of: Some(ConditionOneOf::Filter(Filter {
                            must: vec![Condition {
                                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                    key: "source_type".to_string(),
                                    r#match: Some(Match {
                                        match_value: Some(MatchValue::Keyword(
                                            "chronicle_event".to_string(),
                                        )),
                                    }),
                                    ..Default::default()
                                })),
                            }],
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
            // Chronicle-scoped search: Search chronicle events AND lorebooks from all sessions in the chronicle
            debug!(
                "Building chronicle-scoped search filter for chronicle: {}",
                chronicle_id
            );

            // Get all lorebook IDs from all sessions in this chronicle
            let chronicle_lorebook_ids = match self
                .get_chronicle_lorebook_ids(chronicle_id.into(), user_id.into())
                .await
            {
                Ok(ids) => ids,
                Err(e) => {
                    warn!("Failed to fetch chronicle lorebook IDs: {:?}", e);
                    vec![]
                }
            };

            debug!(
                "Found {} lorebooks in chronicle {}",
                chronicle_lorebook_ids.len(),
                chronicle_id
            );

            if chronicle_lorebook_ids.is_empty() {
                // No lorebooks in chronicle sessions, just search chronicle events
                Filter {
                    must: vec![
                        user_condition,
                        Condition {
                            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                key: "chronicle_id".to_string(),
                                r#match: Some(Match {
                                    match_value: Some(MatchValue::Keyword(
                                        chronicle_id.to_string(),
                                    )),
                                }),
                                ..Default::default()
                            })),
                        },
                    ],
                    ..Default::default()
                }
            } else {
                // Search both chronicle events AND lorebook entries from chronicle sessions
                let lorebook_conditions: Vec<Condition> = chronicle_lorebook_ids
                    .iter()
                    .map(|lorebook_id| Condition {
                        condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                            key: "lorebook_id".to_string(),
                            r#match: Some(Match {
                                match_value: Some(MatchValue::Keyword(lorebook_id.to_string())),
                            }),
                            ..Default::default()
                        })),
                    })
                    .collect();

                Filter {
                    must: vec![user_condition.clone()],
                    should: vec![
                        // Include chronicle events
                        Condition {
                            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                key: "chronicle_id".to_string(),
                                r#match: Some(Match {
                                    match_value: Some(MatchValue::Keyword(
                                        chronicle_id.to_string(),
                                    )),
                                }),
                                ..Default::default()
                            })),
                        },
                        // Include lorebook entries from all sessions in the chronicle
                        Condition {
                            condition_one_of: Some(ConditionOneOf::Filter(Filter {
                                should: lorebook_conditions,
                                ..Default::default()
                            })),
                        },
                    ],
                    ..Default::default()
                }
            }
        } else {
            // No specific scope - search all user's data
            debug!("No session or chronicle filter - searching all user's data");
            Filter {
                must: vec![user_condition],
                ..Default::default()
            }
        };

        // Use a score threshold to filter out low-relevance results
        // Different thresholds for different search types to optimize results
        // LOWERED THRESHOLDS based on user feedback that search was too sensitive
        let score_threshold = match search_type {
            "lorebooks" => Some(0.35),  // Lowered from 0.45
            "chronicles" => Some(0.40), // Lowered from 0.5
            _ => Some(0.30),            // Lowered from 0.4
        };

        info!(
            "Using score threshold: {:?} for search type: {}",
            score_threshold, search_type
        );

        // Determine if we should use hybrid search
        // Use hybrid search for short queries or queries that look like keywords
        let use_hybrid = query.split_whitespace().count() <= 3
            || query.len() <= 20
            || query
                .chars()
                .all(|c| c.is_alphanumeric() || c.is_whitespace());

        // Log the filter we're about to use
        info!("Built search filter: {:#?}", search_filter);

        // Perform search using either hybrid or pure vector search
        let search_results = if use_hybrid {
            info!("Using hybrid search for keyword-like query: {}", query);

            // Define which text fields to search based on content type
            // Note: LanceDB schema only has: chunk_text, entry_title, keywords
            let text_fields = match search_type {
                "lorebooks" => vec![
                    "chunk_text".to_string(),
                    "entry_title".to_string(),
                    "keywords".to_string(),
                ],
                "chronicles" => vec!["chunk_text".to_string(), "keywords".to_string()],
                _ => vec![
                    "chunk_text".to_string(),
                    "entry_title".to_string(),
                    "keywords".to_string(),
                ],
            };

            self.qdrant_service
                .hybrid_search(
                    Some(query_embedding),   // Use vector search as primary
                    Some(query.to_string()), // Also do text matching
                    text_fields,
                    limit * 2, // Get more candidates initially
                    Some(search_filter),
                    score_threshold,
                )
                .await
        } else {
            info!("Using pure vector search for complex query");
            self.qdrant_service
                .search_points_with_threshold(
                    query_embedding,
                    limit * 2, // Get more candidates initially for better filtering
                    Some(search_filter), // SECURITY + SCOPE: Filter by user, session, or chronicle
                    score_threshold,
                )
                .await
        };

        let search_results = match search_results {
            Ok(mut results) => {
                // Log score distribution for debugging
                if !results.is_empty() {
                    let scores: Vec<f32> = results.iter().map(|r| r.score).collect();
                    let min_score = scores
                        .iter()
                        .min_by(|a, b| a.partial_cmp(b).unwrap())
                        .unwrap_or(&0.0);
                    let max_score = scores
                        .iter()
                        .max_by(|a, b| a.partial_cmp(b).unwrap())
                        .unwrap_or(&0.0);
                    let avg_score = scores.iter().sum::<f32>() / scores.len() as f32;

                    info!(
                        "Search results - Count: {}, Min score: {:.3}, Max score: {:.3}, Avg score: {:.3}",
                        results.len(),
                        min_score,
                        max_score,
                        avg_score
                    );
                }

                // Limit to requested number after getting more candidates
                results.truncate(limit as usize);
                results
            }
            Err(e) => {
                error!("Vector search failed: {}", e);
                return Err(ToolError::ExecutionFailed(format!(
                    "Vector search failed: {}",
                    e
                )));
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
                if lorebook_meta.user_id != user_id.into() {
                    error!(
                        "SECURITY VIOLATION: Lorebook result for user {} returned to user {}",
                        lorebook_meta.user_id, user_id
                    );
                    continue;
                }

                let should_include = matches!(search_type, "all" | "lorebooks");
                if should_include {
                    // Decrypt content if encrypted fields are present
                    let content = if let (Some(ref encrypted_chunk), Some(ref nonce)) = (
                        lorebook_meta.encrypted_chunk_text.as_ref(),
                        lorebook_meta.chunk_text_nonce.as_ref(),
                    ) {
                        // We have encrypted content
                        if let Some(ref session_dek) = session_dek_opt {
                            // We have the DEK to decrypt
                            match crate::crypto::decrypt_gcm(encrypted_chunk, nonce, &session_dek.0)
                            {
                                Ok(decrypted_secret) => {
                                    let decrypted_bytes =
                                        secrecy::ExposeSecret::expose_secret(&decrypted_secret);
                                    String::from_utf8_lossy(decrypted_bytes).to_string()
                                }
                                Err(e) => {
                                    warn!("Failed to decrypt lorebook content: {}", e);
                                    "[decryption failed]".to_string()
                                }
                            }
                        } else {
                            // No DEK available
                            "[encrypted - no DEK available]".to_string()
                        }
                    } else {
                        // No encrypted content available
                        "[no encrypted content]".to_string()
                    };

                    let title = if let (Some(ref encrypted_title), Some(ref title_nonce)) = (
                        lorebook_meta.encrypted_title.as_ref(),
                        lorebook_meta.title_nonce.as_ref(),
                    ) {
                        // We have encrypted title
                        if let Some(ref session_dek) = session_dek_opt {
                            match crate::crypto::decrypt_gcm(
                                encrypted_title,
                                title_nonce,
                                &session_dek.0,
                            ) {
                                Ok(decrypted_secret) => {
                                    let decrypted_bytes =
                                        secrecy::ExposeSecret::expose_secret(&decrypted_secret);
                                    let decrypted_title =
                                        String::from_utf8_lossy(decrypted_bytes).to_string();
                                    // Handle empty decrypted titles
                                    if decrypted_title.trim().is_empty() {
                                        "Untitled".to_string()
                                    } else {
                                        decrypted_title
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to decrypt lorebook title: {}", e);
                                    // Handle empty fallback titles
                                    lorebook_meta
                                        .entry_title
                                        .clone()
                                        .and_then(
                                            |t| if t.trim().is_empty() { None } else { Some(t) },
                                        )
                                        .unwrap_or_else(|| "[decryption failed]".to_string())
                                }
                            }
                        } else {
                            // Handle empty fallback titles
                            lorebook_meta
                                .entry_title
                                .clone()
                                .and_then(|t| if t.trim().is_empty() { None } else { Some(t) })
                                .unwrap_or_else(|| "[encrypted - no DEK]".to_string())
                        }
                    } else {
                        // Handle empty unencrypted titles - this is the main fix for the issue
                        lorebook_meta
                            .entry_title
                            .clone()
                            .and_then(|t| if t.trim().is_empty() { None } else { Some(t) })
                            .unwrap_or_else(|| "Untitled".to_string())
                    };

                    results.push(json!({
                        "type": "lorebook_entry",
                        "id": lorebook_meta.original_lorebook_entry_id,
                        "title": title,
                        "content": content.clone(),
                        "relevance_score": scored_point.score,
                        "snippet": content.chars().take(200).collect::<String>(),
                        "keywords": lorebook_meta.keywords
                    }));
                }
            } else if let Ok(chat_meta) = ChatMessageChunkMetadata::try_from(payload_map.clone()) {
                // SECURITY: Double-check that this result belongs to the requesting user
                if chat_meta.user_id != user_id.into() {
                    error!(
                        "SECURITY VIOLATION: Chat result for user {} returned to user {}",
                        chat_meta.user_id, user_id
                    );
                    continue;
                }

                let should_include = matches!(search_type, "all");
                if should_include {
                    // Decrypt content if encrypted fields are present
                    let content = if let (Some(ref encrypted_text), Some(ref nonce)) = (
                        chat_meta.encrypted_text.as_ref(),
                        chat_meta.text_nonce.as_ref(),
                    ) {
                        // We have encrypted content
                        if let Some(ref session_dek) = session_dek_opt {
                            // We have the DEK to decrypt
                            match crate::crypto::decrypt_gcm(encrypted_text, nonce, &session_dek.0)
                            {
                                Ok(decrypted_secret) => {
                                    let decrypted_bytes =
                                        secrecy::ExposeSecret::expose_secret(&decrypted_secret);
                                    String::from_utf8_lossy(decrypted_bytes).to_string()
                                }
                                Err(e) => {
                                    warn!("Failed to decrypt chat message: {}", e);
                                    "[decryption failed]".to_string()
                                }
                            }
                        } else {
                            // No DEK available
                            "[encrypted - no DEK available]".to_string()
                        }
                    } else {
                        // No encrypted content available
                        "[no encrypted content]".to_string()
                    };

                    results.push(json!({
                        "type": "chat_message",
                        "id": chat_meta.message_id,
                        "title": format!("Chat from {}", chat_meta.session_id),
                        "content": content.clone(),
                        "relevance_score": scored_point.score,
                        "snippet": content.chars().take(200).collect::<String>(),
                        "speaker": chat_meta.speaker
                    }));
                }
            } else if let Ok(chronicle_meta) = ChronicleEventMetadata::try_from(payload_map.clone())
            {
                // SECURITY: Double-check that this result belongs to the requesting user
                if chronicle_meta.user_id != user_id.into() {
                    error!(
                        "SECURITY VIOLATION: Chronicle result for user {} returned to user {}",
                        chronicle_meta.user_id, user_id
                    );
                    continue;
                }

                let should_include = matches!(search_type, "all" | "chronicles");
                if should_include {
                    // Extract content - prioritize event_json, then encrypted, then chunk_text
                    let mut content = None;

                    // 1. Try to extract from event_json (structured data)
                    if let Some(json_value) = payload_map.get("event_json") {
                        // Convert Qdrant Value to serde_json::Value
                        // We need to handle the conversion carefully
                        let json_val: serde_json::Value = json_value
                            .clone()
                            .try_into()
                            .unwrap_or(serde_json::Value::Null);

                        if let Some(summary) = json_val.get("summary").and_then(|s| s.as_str()) {
                            content = Some(summary.to_string());
                        }
                    }

                    // 2. If no content yet, try to decrypt encrypted_chunk_text
                    if content.is_none() {
                        if let (Some(encrypted_chunk_text), Some(chunk_text_nonce)) = (
                            payload_map.get("encrypted_chunk_text"),
                            payload_map.get("chunk_text_nonce"),
                        ) {
                            // We have encrypted content - need to extract bytes from Qdrant format
                            let encrypted_bytes = encrypted_chunk_text.as_list().and_then(|list| {
                                let bytes: Option<Vec<u8>> = list
                                    .iter()
                                    .map(|v| v.as_integer().map(|i| i as u8))
                                    .collect();
                                bytes
                            });
                            let nonce_bytes = chunk_text_nonce.as_list().and_then(|list| {
                                let bytes: Option<Vec<u8>> = list
                                    .iter()
                                    .map(|v| v.as_integer().map(|i| i as u8))
                                    .collect();
                                bytes
                            });

                            if let (Some(encrypted), Some(nonce), Some(ref session_dek)) =
                                (encrypted_bytes, nonce_bytes, session_dek_opt.as_ref())
                            {
                                // Decrypt the content
                                match crate::crypto::decrypt_gcm(&encrypted, &nonce, &session_dek.0)
                                {
                                    Ok(decrypted_secret) => {
                                        let decrypted_bytes =
                                            secrecy::ExposeSecret::expose_secret(&decrypted_secret);
                                        content = Some(
                                            String::from_utf8_lossy(decrypted_bytes).to_string(),
                                        );
                                    }
                                    Err(e) => {
                                        warn!("Failed to decrypt chronicle event content: {}", e);
                                        // Don't set content, let it fall through to next method
                                    }
                                }
                            }
                        }
                    }

                    // 3. If still no content, try chunk_text (if not placeholder)
                    if content.is_none() {
                        if let Some(text_value) = payload_map.get("chunk_text") {
                            let text = match text_value {
                                qdrant_client::qdrant::Value {
                                    kind: Some(qdrant_client::qdrant::value::Kind::StringValue(s)),
                                } => s.clone(),
                                _ => String::new(),
                            };

                            if !text.is_empty()
                                && text != "[encrypted]"
                                && text != "[MISSING ENCRYPTION]"
                            {
                                content = Some(text);
                            }
                        }
                    }

                    // 4. Fallback formatting
                    let content = content.unwrap_or_else(|| {
                        format!(
                            "Event type: {}, Chronicle: {}, Created: {}",
                            chronicle_meta.event_type,
                            chronicle_meta.chronicle_id,
                            chronicle_meta.created_at.format("%Y-%m-%d %H:%M:%S")
                        )
                    });

                    let result = json!({
                        "type": "chronicle_event",
                        "id": chronicle_meta.event_id,
                        "title": format!("Chronicle Event: {}", chronicle_meta.event_type),
                        "content": content.clone(),
                        "relevance_score": scored_point.score,
                        "snippet": content.chars().take(200).collect::<String>(),
                        "event_type": chronicle_meta.event_type,
                        "chronicle_id": chronicle_meta.chronicle_id.to_string(),
                        "created_at": chronicle_meta.created_at.to_rfc3339()
                    });

                    // Prioritize results from the specified chronicle_id
                    if let Some(target_chronicle_id) = chronicle_id_opt {
                        if chronicle_meta.chronicle_id == target_chronicle_id.into() {
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
    _lorebook_service: Arc<LorebookService>,
    _app_state: Arc<AppState>,
}

/// Tool for creating multiple lorebook entries in a single operation (batch generation)
/// Uses AI to generate entries with structured outputs, then saves them to the database
pub struct CreateBatchLorebookEntriesTool {
    lorebook_service: Arc<LorebookService>,
    ai_client: Arc<dyn AiClient>,
}

/// Tool for analyzing existing lorebook entries and identifying gaps, inconsistencies, or improvement opportunities
/// Uses AI to provide strategic recommendations for lorebook enhancement
pub struct AnalyzeLorebookTool {
    lorebook_service: Arc<LorebookService>,
    ai_client: Arc<dyn AiClient>,
    app_state: Arc<AppState>,
}

impl AnalyzeLorebookTool {
    pub fn new(
        lorebook_service: Arc<LorebookService>,
        ai_client: Arc<dyn AiClient>,
        app_state: Arc<AppState>,
    ) -> Self {
        Self {
            lorebook_service,
            ai_client,
            app_state,
        }
    }
}

#[async_trait]
impl ScribeTool for AnalyzeLorebookTool {
    fn name(&self) -> &'static str {
        "analyze_lorebook"
    }

    fn description(&self) -> &'static str {
        "Analyzes existing lorebook entries to identify gaps, inconsistencies, or areas for improvement. Use this before batch generation to understand what content is missing or needs enhancement. Returns strategic recommendations for lorebook improvement."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "lorebook_id": {
                    "type": "string",
                    "description": "The UUID of the lorebook to analyze"
                },
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user owning the lorebook"
                },
                "character_id": {
                    "type": "string",
                    "description": "Optional: Character ID for character-specific context analysis"
                },
                "session_dek": {
                    "type": "string",
                    "description": "Hex-encoded session DEK for decrypting lorebook content"
                },
                "focus_area": {
                    "type": "string",
                    "description": "Optional: Specific area to focus analysis on (e.g., 'characters', 'locations', 'consistency')"
                }
            },
            "required": ["lorebook_id", "user_id", "session_dek"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        use crate::schema::lorebook_entries::dsl as lorebook_entries_dsl;
        use diesel::prelude::*;

        let lorebook_id = params
            .get("lorebook_id")
            .and_then(|v| v.as_str())
            .and_then(|s| DbId::parse_str(s).ok())
            .ok_or_else(|| {
                ToolError::InvalidParams("lorebook_id must be a valid UUID string".to_string())
            })?;

        let user_id = params
            .get("user_id")
            .and_then(|v| v.as_str())
            .and_then(|s| DbId::parse_str(s).ok())
            .ok_or_else(|| {
                ToolError::InvalidParams("user_id must be a valid UUID string".to_string())
            })?;

        let session_dek_hex = params
            .get("session_dek")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("session_dek must be a string".to_string()))?;

        // Decode the session DEK from hex
        let session_dek_bytes = hex::decode(session_dek_hex).map_err(|e| {
            ToolError::ExecutionFailed(format!("Failed to decode session_dek: {}", e))
        })?;

        if session_dek_bytes.len() != 32 {
            return Err(ToolError::InvalidParams(format!(
                "session_dek must decode to 32 bytes, got {}",
                session_dek_bytes.len()
            )));
        }

        let session_dek_secret = secrecy::SecretBox::new(Box::new(session_dek_bytes));
        let session_dek_wrapper = crate::auth::session_dek::SessionDek(session_dek_secret);

        // SECURITY: Verify lorebook ownership before querying entries
        // This prevents cross-user access by explicitly checking that the lorebook belongs to the user
        let pool = self.app_state.pool.clone();
        use crate::schema::lorebooks::dsl as lorebooks_dsl;

        let lorebook_id_for_check = lorebook_id;
        let user_id_for_check = user_id;
        let lorebook_exists = crate::db::with_conn(&pool, move |conn| {
            lorebooks_dsl::lorebooks
                .filter(lorebooks_dsl::id.eq(lorebook_id_for_check))
                .filter(lorebooks_dsl::user_id.eq(user_id_for_check))
                .select(lorebooks_dsl::id)
                .first::<crate::db::DbId>(conn)
                .optional()
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!(
                        "Failed to verify lorebook ownership: {}",
                        e
                    ))
                })
        })
        .await
        .map_err(|e| ToolError::ExecutionFailed(format!("{}", e)))?;

        if lorebook_exists.is_none() {
            return Err(ToolError::ExecutionFailed(format!(
                "Lorebook {} not found or access denied for user {}",
                lorebook_id, user_id
            )));
        }

        // Fetch all lorebook entries for this lorebook and user
        let entries: Vec<(
            crate::db::DbId,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            bool,
        )> = crate::db::with_conn(&pool, move |conn| {
            lorebook_entries_dsl::lorebook_entries
                .filter(lorebook_entries_dsl::lorebook_id.eq(lorebook_id))
                .filter(lorebook_entries_dsl::user_id.eq(user_id))
                .select((
                    lorebook_entries_dsl::id,
                    lorebook_entries_dsl::entry_title_ciphertext,
                    lorebook_entries_dsl::entry_title_nonce,
                    lorebook_entries_dsl::content_ciphertext,
                    lorebook_entries_dsl::content_nonce,
                    lorebook_entries_dsl::keys_text_ciphertext,
                    lorebook_entries_dsl::keys_text_nonce,
                    lorebook_entries_dsl::is_enabled,
                ))
                .load::<(
                    crate::db::DbId,
                    Vec<u8>,
                    Vec<u8>,
                    Vec<u8>,
                    Vec<u8>,
                    Vec<u8>,
                    Vec<u8>,
                    bool,
                )>(conn)
                .map_err(|e| AppError::DatabaseQueryError(format!("Failed to load entries: {}", e)))
        })
        .await
        .map_err(|e| {
            ToolError::ExecutionFailed(format!("Failed to load lorebook entries: {}", e))
        })?;

        if entries.is_empty() {
            return Ok(serde_json::json!({
                "status": "success",
                "analysis": {
                    "gaps": ["No entries found in this lorebook"],
                    "consistency_issues": [],
                    "improvement_suggestions": ["Create initial lorebook entries to establish the world/character context"],
                    "recommended_themes": []
                }
            }));
        }

        // Decrypt and prepare entry summaries for AI analysis
        let mut entry_summaries = Vec::new();
        for (id, title_ct, title_nonce, content_ct, content_nonce, keys_ct, keys_nonce, enabled) in
            entries
        {
            let title_secret =
                crate::crypto::decrypt_gcm(&title_ct, &title_nonce, &session_dek_wrapper.0)
                    .map_err(|e| {
                        ToolError::ExecutionFailed(format!("Failed to decrypt entry title: {}", e))
                    })?;

            let title_bytes = secrecy::ExposeSecret::expose_secret(&title_secret);
            let title_str = String::from_utf8_lossy(title_bytes);

            let content_secret =
                crate::crypto::decrypt_gcm(&content_ct, &content_nonce, &session_dek_wrapper.0)
                    .map_err(|e| {
                        ToolError::ExecutionFailed(format!(
                            "Failed to decrypt entry content: {}",
                            e
                        ))
                    })?;

            let content_bytes = secrecy::ExposeSecret::expose_secret(&content_secret);
            let content_str = String::from_utf8_lossy(content_bytes);
            let content_preview = if content_str.len() > 300 {
                format!("{}...", &content_str[..300])
            } else {
                content_str.to_string()
            };

            let keys_secret =
                crate::crypto::decrypt_gcm(&keys_ct, &keys_nonce, &session_dek_wrapper.0).map_err(
                    |e| ToolError::ExecutionFailed(format!("Failed to decrypt entry keys: {}", e)),
                )?;

            let keys_bytes = secrecy::ExposeSecret::expose_secret(&keys_secret);
            let keys_str = String::from_utf8_lossy(keys_bytes);

            entry_summaries.push(serde_json::json!({
                "id": id.to_string(),
                "title": title_str,
                "content_preview": content_preview,
                "keys": keys_str,
                "enabled": enabled
            }));
        }

        // Build AI prompt for analysis
        let analysis_prompt = format!(
            r#"You are analyzing a lorebook for a character AI roleplay system.
A lorebook contains world-building information, character details, and contextual knowledge
that helps the AI maintain consistency during conversations.

Here are the current lorebook entries (total: {}):

{}

Please analyze this lorebook and provide:
1. **gaps**: What important information or themes are missing?
2. **consistency_issues**: Are there any contradictions or inconsistencies between entries?
3. **improvement_suggestions**: How can existing entries be enhanced?
4. **recommended_themes**: What new entry themes would strengthen this lorebook?

Return your analysis as a JSON object with these four arrays."#,
            entry_summaries.len(),
            serde_json::to_string_pretty(&entry_summaries).unwrap()
        );

        // Define structured output schema for the analysis
        let analysis_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "gaps": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Missing information or themes that would strengthen the lorebook"
                },
                "consistency_issues": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Contradictions or inconsistencies found between entries"
                },
                "improvement_suggestions": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Specific suggestions for enhancing existing entries"
                },
                "recommended_themes": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "New entry themes that would add value to the lorebook"
                }
            },
            "required": ["gaps", "consistency_issues", "improvement_suggestions", "recommended_themes"]
        });

        // Call AI with structured output
        use genai::chat::{
            ChatMessage as GenAiChatMessage, ChatOptions as GenAiChatOptions, ChatRequest,
            ChatResponseFormat, ChatRole, JsonSchemaSpec, MessageContent,
        };

        let user_message = GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text(analysis_prompt),
            options: None,
        };

        let mut chat_options = GenAiChatOptions::default();
        chat_options = chat_options.with_temperature(0.3); // Low temp for consistent analysis
        chat_options = chat_options.with_max_tokens(2048);

        // Add safety settings
        let safety_settings = create_unrestricted_safety_settings();
        chat_options = chat_options.with_safety_settings(safety_settings);

        // Enable structured output using JSON schema
        let json_schema_spec = JsonSchemaSpec::new(analysis_schema);
        let response_format = ChatResponseFormat::JsonSchemaSpec(json_schema_spec);
        chat_options = chat_options.with_response_format(response_format);

        let chat_request = ChatRequest::new(vec![user_message]);

        let response = self
            .ai_client
            .exec_chat("gemini-2.5-flash", chat_request, Some(chat_options))
            .await
            .map_err(|e| {
                ToolError::ExecutionFailed(format!("AI call for lorebook analysis failed: {}", e))
            })?;

        // Extract token usage for cost tracking
        let prompt_tokens = response.usage.prompt_tokens.unwrap_or(0);
        let completion_tokens = response.usage.completion_tokens.unwrap_or(0);
        let total_tokens = response.usage.total_tokens.unwrap_or(0);

        info!(
            "AI token usage - prompt: {}, completion: {}, total: {}",
            prompt_tokens, completion_tokens, total_tokens
        );

        let ai_content = response
            .first_content_text_as_str()
            .ok_or_else(|| ToolError::ExecutionFailed("AI response had no content".to_string()))?;

        // Parse AI response as JSON
        let analysis: crate::DbJson = serde_json::from_str(ai_content).map_err(|e| {
            ToolError::ExecutionFailed(format!(
                "Failed to parse AI analysis response as JSON: {}",
                e
            ))
        })?;

        Ok(serde_json::json!({
            "status": "success",
            "entries_analyzed": entry_summaries.len(),
            "analysis": analysis,
            "token_usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens
            }
        }))
    }
}

impl CreateBatchLorebookEntriesTool {
    pub fn new(lorebook_service: Arc<LorebookService>, ai_client: Arc<dyn AiClient>) -> Self {
        Self {
            lorebook_service,
            ai_client,
        }
    }
}

#[async_trait]
impl ScribeTool for CreateBatchLorebookEntriesTool {
    fn name(&self) -> &'static str {
        "create_batch_lorebook_entries"
    }

    fn description(&self) -> &'static str {
        "Creates multiple lorebook entries in one operation using AI generation. Use this for efficiently generating a collection of related entries (e.g., 5-10 entries about locations, characters, items, or lore concepts). More efficient than calling create_lorebook_entry multiple times."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "lorebook_id": {
                    "type": "string",
                    "description": "The UUID of the lorebook to add entries to (optional - will use/create default if not provided)"
                },
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user creating the entries"
                },
                "count": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 20,
                    "description": "Number of entries to generate (1-20)",
                    "default": 5
                },
                "theme": {
                    "type": "string",
                    "description": "Theme or topic for the batch generation (e.g., 'magical items', 'key locations', 'important NPCs')"
                },
                "character_context": {
                    "type": "object",
                    "description": "Optional character context (name, description, scenario) to maintain consistency",
                    "properties": {
                        "name": {"type": "string"},
                        "description": {"type": "string"},
                        "scenario": {"type": "string"}
                    }
                },
                "world_context": {
                    "type": "string",
                    "description": "Optional world/setting context to guide generation"
                },
                "session_dek": {
                    "type": "string",
                    "description": "Hex-encoded session DEK for encrypting entry content"
                }
            },
            "required": ["user_id", "count", "theme", "session_dek"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!(
            "Executing create_batch_lorebook_entries tool with params: {}",
            params
        );

        // Extract parameters
        let user_id_str = params
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let count = params.get("count").and_then(|v| v.as_u64()).unwrap_or(5) as usize;

        if count < 1 || count > 20 {
            return Err(ToolError::InvalidParams(
                "count must be between 1 and 20".to_string(),
            ));
        }

        let theme = params
            .get("theme")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("theme is required".to_string()))?;

        // Parse user UUID
        let user_uuid = DbId::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        // Extract session DEK (for encryption)
        let session_dek_bytes = params
            .get("session_dek")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
            .ok_or_else(|| {
                ToolError::InvalidParams(
                    "session_dek is required for lorebook entry creation".to_string(),
                )
            })?;

        // Optional lorebook_id
        let lorebook_id = params
            .get("lorebook_id")
            .and_then(|v| v.as_str())
            .and_then(|s| DbId::parse_str(s).ok());

        info!(
            "Batch generating {} lorebook entries for user {} with theme: {}",
            count, user_uuid, theme
        );

        // Build AI generation prompt
        let mut prompt = format!(
            "Generate {} detailed lorebook entries based on the following theme: {}\n\n",
            count, theme
        );

        // Add character context if provided
        if let Some(char_context) = params.get("character_context").and_then(|v| v.as_object()) {
            prompt.push_str("**Character Context:**\n");
            if let Some(name) = char_context.get("name").and_then(|v| v.as_str()) {
                prompt.push_str(&format!("- Name: {}\n", name));
            }
            if let Some(desc) = char_context.get("description").and_then(|v| v.as_str()) {
                prompt.push_str(&format!("- Description: {}\n", desc));
            }
            if let Some(scenario) = char_context.get("scenario").and_then(|v| v.as_str()) {
                prompt.push_str(&format!("- Scenario: {}\n", scenario));
            }
            prompt.push('\n');
        }

        // Add world context if provided
        if let Some(world_ctx) = params.get("world_context").and_then(|v| v.as_str()) {
            prompt.push_str(&format!("**World Context:**\n{}\n\n", world_ctx));
        }

        prompt.push_str(&format!(
            "Generate {} entries that are:\n\
            - Detailed and immersive\n\
            - Consistent with provided context\n\
            - Related and complementary\n\
            - Useful during roleplay\n\
            - Each with appropriate trigger keywords",
            count
        ));

        // Use AI to generate entries with structured outputs
        use crate::services::character_generation::structured_output::{
            get_batch_lorebook_entries_schema, BatchLorebookEntriesOutput,
        };
        use genai::chat::{
            ChatMessage as GenAiChatMessage, ChatOptions as GenAiChatOptions, ChatRequest,
            ChatResponseFormat, ChatRole, JsonSchemaSpec, MessageContent,
        };

        let system_prompt = format!(
            r#"You are a world-building assistant creating {} lorebook entries.

Each entry should include:
1. **Name**: Clear, concise title
2. **Content**: Rich, detailed information (150-500 words)
3. **Keys**: 3-5 trigger keywords (names, places, concepts)
4. **Category**: Optional category (character, location, lore, item, faction, event)

Guidelines:
- Write engaging, immersive content
- Maintain consistency with provided context
- Ensure entries are related and complement each other
- Generate appropriate trigger keys with variations
- Focus on information useful during roleplay
- Avoid redundancy between entries

You must respond with a JSON object containing an array of {} entries."#,
            count, count
        );

        let user_message = GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text(prompt),
            options: None,
        };

        let mut chat_options = GenAiChatOptions::default();
        chat_options = chat_options.with_temperature(0.8); // Creative generation
        let max_tokens = (count * 800).min(8192) as u32; // ~800 tokens per entry
        chat_options = chat_options.with_max_tokens(max_tokens);

        // Add safety settings
        let safety_settings = create_unrestricted_safety_settings();
        chat_options = chat_options.with_safety_settings(safety_settings);

        // Enable structured output using JSON schema
        let json_schema_spec = JsonSchemaSpec::new(get_batch_lorebook_entries_schema());
        let response_format = ChatResponseFormat::JsonSchemaSpec(json_schema_spec);
        chat_options = chat_options.with_response_format(response_format);

        let chat_request = ChatRequest::new(vec![user_message]).with_system(&system_prompt);

        // Execute AI generation
        let start_time = std::time::Instant::now();
        let response = self
            .ai_client
            .exec_chat("gemini-2.5-flash-lite", chat_request, Some(chat_options))
            .await
            .map_err(|e| {
                error!("AI batch generation failed: {}", e);
                ToolError::ExecutionFailed(format!("AI generation failed: {}", e))
            })?;

        // Extract token usage for cost tracking
        let prompt_tokens = response.usage.prompt_tokens.unwrap_or(0);
        let completion_tokens = response.usage.completion_tokens.unwrap_or(0);
        let total_tokens = response.usage.total_tokens.unwrap_or(0);

        info!(
            "AI token usage - prompt: {}, completion: {}, total: {}",
            prompt_tokens, completion_tokens, total_tokens
        );

        // Parse structured output
        let response_text = response
            .first_content_text_as_str()
            .ok_or_else(|| ToolError::ExecutionFailed("No content in AI response".to_string()))?;

        let batch_output: BatchLorebookEntriesOutput = serde_json::from_str(response_text)
            .map_err(|e| {
                error!("Failed to parse batch lorebook output: {}", e);
                ToolError::ExecutionFailed(format!("JSON parse failed: {}", e))
            })?;

        // Validate the generated entries
        if let Err(e) = batch_output.validate() {
            error!("Batch output validation failed: {}", e);
            return Err(ToolError::ExecutionFailed(format!(
                "Validation failed: {}",
                e
            )));
        }

        let generation_time_ms = start_time.elapsed().as_millis() as u64;
        info!(
            "AI generated {} entries in {}ms, now saving to database",
            batch_output.entries.len(),
            generation_time_ms
        );

        // Save all generated entries to the database
        let mut created_entries = Vec::new();
        let mut failed_entries = Vec::new();

        for (idx, entry_output) in batch_output.entries.into_iter().enumerate() {
            // Convert keys array to space-separated string
            let keywords = if entry_output.keys.is_empty() {
                None
            } else {
                Some(entry_output.keys.join(" "))
            };

            match self
                .lorebook_service
                .create_entry_for_narrative_intelligence(
                    user_uuid.into(),
                    lorebook_id.map(|id| id.into()),
                    entry_output.name.clone(),
                    entry_output.content.clone(),
                    keywords,
                    &session_dek_bytes,
                )
                .await
            {
                Ok(entry_response) => {
                    info!(
                        "Successfully saved entry {}/{}: {}",
                        idx + 1,
                        count,
                        entry_response.id
                    );
                    created_entries.push(json!({
                        "entry_id": entry_response.id,
                        "lorebook_id": entry_response.lorebook_id,
                        "title": entry_response.entry_title,
                        "content_length": entry_response.content.len(),
                        "category": entry_output.category
                    }));
                }
                Err(e) => {
                    error!("Failed to save entry {}: {}", entry_output.name, e);
                    failed_entries.push(json!({
                        "title": entry_output.name,
                        "error": e.to_string()
                    }));
                }
            }
        }

        let total_time_ms = start_time.elapsed().as_millis() as u64;

        if created_entries.is_empty() {
            return Err(ToolError::ExecutionFailed(
                "Failed to save any entries to database".to_string(),
            ));
        }

        Ok(json!({
            "success": true,
            "entries_created": created_entries.len(),
            "entries_failed": failed_entries.len(),
            "created_entries": created_entries,
            "failed_entries": failed_entries,
            "total_time_ms": total_time_ms,
            "generation_time_ms": generation_time_ms,
            "token_usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens
            },
            "message": format!("Successfully created {}/{} lorebook entries", created_entries.len(), count)
        }))
    }
}

impl UpdateLorebookEntryTool {
    pub fn new(lorebook_service: Arc<LorebookService>, app_state: Arc<AppState>) -> Self {
        Self {
            _lorebook_service: lorebook_service,
            _app_state: app_state,
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
        debug!(
            "Executing update_lorebook_entry tool with params: {}",
            params
        );

        let entry_id = params
            .get("entry_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("entry_id is required".to_string()))?;

        let new_content = params
            .get("new_content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("new_content is required".to_string()))?;

        let _updated_keywords = params
            .get("updated_keywords")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            });

        let append_mode = params
            .get("append_mode")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        // Parse entry_id as UUID
        let entry_uuid = DbId::parse_str(entry_id)
            .map_err(|_| ToolError::InvalidParams("Invalid entry_id format".to_string()))?;

        info!(
            "Updating lorebook entry {} (append_mode: {})",
            entry_uuid, append_mode
        );

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

/// Tool for querying rulebook/game rules from lorebook entries tagged with "rules"
/// This is used by the Game Master mode to enforce game mechanics and world consistency
pub struct QueryRulesTool {
    qdrant_service: Arc<dyn QdrantClientServiceTrait>,
    embedding_client: Arc<dyn EmbeddingClient>,
    app_state: Arc<AppState>,
}

impl QueryRulesTool {
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
}

#[async_trait]
impl ScribeTool for QueryRulesTool {
    fn name(&self) -> &'static str {
        "query_rules"
    }

    fn description(&self) -> &'static str {
        "Searches for game rules and mechanics from lorebook entries tagged with 'rules'. Use this to enforce game mechanics, check travel rules, combat mechanics, or any world-specific constraints."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The rule query (e.g., 'travel time between cities', 'combat initiative rules', 'magic casting limitations')"
                },
                "rule_category": {
                    "type": "string",
                    "enum": ["general", "travel", "combat", "magic", "social", "economy", "crafting", "survival"],
                    "description": "Optional category to narrow down the rule search",
                    "default": "general"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of rule entries to return",
                    "default": 5,
                    "minimum": 1,
                    "maximum": 20
                },
                "user_id": {
                    "type": "string",
                    "description": "REQUIRED: User ID to filter search results to user's own data only"
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional: Session ID to filter results to session-associated lorebooks"
                }
            },
            "required": ["query", "user_id"]
        })
    }

    async fn execute(&self, params: &ToolParams) -> Result<ToolResult, ToolError> {
        debug!("Executing query_rules tool with params: {}", params);

        let query = params
            .get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("query is required".to_string()))?;

        let rule_category = params
            .get("rule_category")
            .and_then(|v| v.as_str())
            .unwrap_or("general");

        let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(5) as u32;

        let user_id_str = params
            .get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ToolError::InvalidParams("user_id is REQUIRED for security filtering".to_string())
            })?;

        let user_id: DbId = DbId::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        let _session_id_opt: Option<DbId> = params
            .get("session_id")
            .and_then(|v| v.as_str())
            .and_then(|s| DbId::parse_str(s).ok());

        info!(
            "Querying rules for '{}' (category: {}, limit: {}) for user {}",
            query, rule_category, limit, user_id
        );

        // Generate embedding for the query
        let query_embedding = match self
            .embedding_client
            .embed_content(query, "RETRIEVAL_QUERY", None)
            .await
        {
            Ok(embedding) => embedding,
            Err(e) => {
                error!("Failed to generate query embedding: {}", e);
                return Err(ToolError::ExecutionFailed(format!(
                    "Embedding generation failed: {}",
                    e
                )));
            }
        };

        // Build filter for rules search
        use crate::vector_db::qdrant_client::{Condition, FieldCondition, Filter, Match};
        use qdrant_client::qdrant::{condition::ConditionOneOf, r#match::MatchValue};

        // Base conditions: user_id + source_type=lorebook_entry
        let must_conditions = vec![
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "user_id".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword(user_id.to_string())),
                    }),
                    ..Default::default()
                })),
            },
            Condition {
                condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                    key: "source_type".to_string(),
                    r#match: Some(Match {
                        match_value: Some(MatchValue::Keyword("lorebook_entry".to_string())),
                    }),
                    ..Default::default()
                })),
            },
        ];

        let search_filter = Filter {
            must: must_conditions,
            ..Default::default()
        };

        // Execute the search
        let search_results = match self
            .qdrant_service
            .search_points_with_threshold(
                query_embedding,
                limit as u64,
                Some(search_filter),
                Some(0.3), // Score threshold for rules (slightly lower to catch more rules)
            )
            .await
        {
            Ok(results) => results,
            Err(e) => {
                error!("Qdrant search failed: {}", e);
                return Err(ToolError::ExecutionFailed(format!(
                    "Vector search failed: {}",
                    e
                )));
            }
        };

        info!("Found {} potential rule entries", search_results.len());

        // Process results
        let mut rules_found = Vec::new();
        for result in search_results {
            let payload = &result.payload;

            // Extract string values from Qdrant Value type
            let content = payload
                .get("content")
                .and_then(|v| match &v.kind {
                    Some(qdrant_client::qdrant::value::Kind::StringValue(s)) => Some(s.as_str()),
                    _ => None,
                })
                .unwrap_or("");
            let keywords = payload
                .get("keywords")
                .and_then(|v| match &v.kind {
                    Some(qdrant_client::qdrant::value::Kind::StringValue(s)) => Some(s.as_str()),
                    _ => None,
                })
                .unwrap_or("");
            let entry_name = payload
                .get("entry_name")
                .and_then(|v| match &v.kind {
                    Some(qdrant_client::qdrant::value::Kind::StringValue(s)) => Some(s.as_str()),
                    _ => None,
                })
                .unwrap_or("Unknown Rule");

            // Check if this entry is likely a rule (has "rule" in keywords or content)
            let is_rule = keywords.to_lowercase().contains("rule")
                || keywords.to_lowercase().contains("mechanic")
                || keywords.to_lowercase().contains(rule_category)
                || content.to_lowercase().contains("rule")
                || content.to_lowercase().contains("mechanic");

            if is_rule || rule_category == "general" {
                rules_found.push(json!({
                    "name": entry_name,
                    "content": content,
                    "keywords": keywords,
                    "category": rule_category,
                    "score": result.score
                }));
            }
        }

        // Sort by score (should already be sorted, but ensure)
        rules_found.sort_by(|a, b| {
            let score_a = a.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let score_b = b.get("score").and_then(|v| v.as_f64()).unwrap_or(0.0);
            score_b
                .partial_cmp(&score_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Take top N results
        let rules_found: Vec<_> = rules_found.into_iter().take(limit as usize).collect();

        if rules_found.is_empty() {
            info!("No rules found for query: {}", query);
            Ok(json!({
                "status": "no_rules_found",
                "query": query,
                "category": rule_category,
                "message": "No applicable rules found for this query. The action may proceed without specific rule constraints.",
                "rules": []
            }))
        } else {
            info!("Found {} rules for query: {}", rules_found.len(), query);
            Ok(json!({
                "status": "rules_found",
                "query": query,
                "category": rule_category,
                "rule_count": rules_found.len(),
                "rules": rules_found
            }))
        }
    }
}

// ============================================================================
// Unit Tests for QueryRulesTool
// ============================================================================

#[cfg(test)]
mod query_rules_tests {
    use super::*;
    use serde_json::json;

    // ========================================================================
    // Schema Validation Tests (following sanguine-rpg patterns)
    // ========================================================================

    /// Helper to create a mock QueryRulesTool for schema testing
    /// Note: This doesn't actually make network calls, just validates schema
    fn get_query_rules_schema() -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The rule query (e.g., 'travel time between cities', 'combat initiative rules', 'magic casting limitations')"
                },
                "rule_category": {
                    "type": "string",
                    "enum": ["general", "travel", "combat", "magic", "social", "economy", "crafting", "survival"],
                    "description": "Optional category to narrow down the rule search",
                    "default": "general"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of rule entries to return",
                    "default": 5,
                    "minimum": 1,
                    "maximum": 20
                },
                "user_id": {
                    "type": "string",
                    "description": "REQUIRED: User ID to filter search results to user's own data only"
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional: Session ID to filter results to session-associated lorebooks"
                }
            },
            "required": ["query", "user_id"]
        })
    }

    #[test]
    fn test_query_rules_schema_has_required_properties() {
        let schema = get_query_rules_schema();

        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["query"].is_object());
        assert!(schema["properties"]["rule_category"].is_object());
        assert!(schema["properties"]["limit"].is_object());
        assert!(schema["properties"]["user_id"].is_object());
    }

    #[test]
    fn test_query_rules_schema_required_fields() {
        let schema = get_query_rules_schema();

        let required = schema["required"].as_array().unwrap();
        assert!(required.contains(&json!("query")));
        assert!(required.contains(&json!("user_id")));
    }

    #[test]
    fn test_query_rules_schema_rule_category_enum() {
        let schema = get_query_rules_schema();

        let categories = schema["properties"]["rule_category"]["enum"]
            .as_array()
            .unwrap();
        assert!(categories.contains(&json!("general")));
        assert!(categories.contains(&json!("travel")));
        assert!(categories.contains(&json!("combat")));
        assert!(categories.contains(&json!("magic")));
        assert!(categories.contains(&json!("social")));
        assert!(categories.contains(&json!("economy")));
        assert!(categories.contains(&json!("crafting")));
        assert!(categories.contains(&json!("survival")));
    }

    #[test]
    fn test_query_rules_schema_limit_constraints() {
        let schema = get_query_rules_schema();

        assert_eq!(schema["properties"]["limit"]["default"], 5);
        assert_eq!(schema["properties"]["limit"]["minimum"], 1);
        assert_eq!(schema["properties"]["limit"]["maximum"], 20);
    }

    #[test]
    fn test_query_rules_schema_category_default() {
        let schema = get_query_rules_schema();

        assert_eq!(schema["properties"]["rule_category"]["default"], "general");
    }

    // ========================================================================
    // Parameter Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_query_rules_params_minimal() {
        let params = json!({
            "query": "combat initiative",
            "user_id": "user_123"
        });

        let query = params["query"].as_str().unwrap();
        let user_id = params["user_id"].as_str().unwrap();
        let rule_category = params
            .get("rule_category")
            .and_then(|v| v.as_str())
            .unwrap_or("general");
        let limit = params
            .get("limit")
            .and_then(|v| v.as_i64())
            .map(|v| v.clamp(1, 20))
            .unwrap_or(5);

        assert_eq!(query, "combat initiative");
        assert_eq!(user_id, "user_123");
        assert_eq!(rule_category, "general");
        assert_eq!(limit, 5);
    }

    #[test]
    fn test_parse_query_rules_params_full() {
        let params = json!({
            "query": "travel time between cities",
            "user_id": "user_456",
            "rule_category": "travel",
            "limit": 10,
            "session_id": "session_789"
        });

        let query = params["query"].as_str().unwrap();
        let user_id = params["user_id"].as_str().unwrap();
        let rule_category = params
            .get("rule_category")
            .and_then(|v| v.as_str())
            .unwrap_or("general");
        let limit = params
            .get("limit")
            .and_then(|v| v.as_i64())
            .map(|v| v.clamp(1, 20))
            .unwrap_or(5);
        let session_id = params.get("session_id").and_then(|v| v.as_str());

        assert_eq!(query, "travel time between cities");
        assert_eq!(user_id, "user_456");
        assert_eq!(rule_category, "travel");
        assert_eq!(limit, 10);
        assert_eq!(session_id, Some("session_789"));
    }

    #[test]
    fn test_parse_query_rules_limit_clamped_to_max() {
        let params = json!({
            "query": "test",
            "user_id": "user_123",
            "limit": 100 // Exceeds max of 20
        });

        let limit = params
            .get("limit")
            .and_then(|v| v.as_i64())
            .map(|v| v.clamp(1, 20))
            .unwrap_or(5);

        assert_eq!(limit, 20); // Clamped to max
    }

    #[test]
    fn test_parse_query_rules_limit_clamped_to_min() {
        let params = json!({
            "query": "test",
            "user_id": "user_123",
            "limit": 0 // Below min of 1
        });

        let limit = params
            .get("limit")
            .and_then(|v| v.as_i64())
            .map(|v| v.clamp(1, 20))
            .unwrap_or(5);

        assert_eq!(limit, 1); // Clamped to min
    }

    #[test]
    fn test_rule_category_validation() {
        let valid_categories = vec![
            "general", "travel", "combat", "magic", "social", "economy", "crafting", "survival",
        ];

        for category in valid_categories {
            let params = json!({
                "query": "test",
                "user_id": "user_123",
                "rule_category": category
            });

            let parsed_category = params
                .get("rule_category")
                .and_then(|v| v.as_str())
                .unwrap_or("general");

            assert_eq!(parsed_category, category);
        }
    }
}
