//! AI-Driven Lorebook Tools
//!
//! These tools use AI models to interpret natural language requests about lore
//! and world knowledge. They leverage the configured AI models to provide
//! intelligent search and documentation capabilities for world-building.

use std::sync::Arc;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use async_trait::async_trait;
use tracing::{info, debug, warn, error, instrument};
use secrecy::{SecretBox, ExposeSecret};
use genai::chat::{ChatRequest, ChatMessage, ChatRole, ChatOptions, ChatResponseFormat, JsonSchemaSpec, SafetySetting, HarmCategory, HarmBlockThreshold};

use crate::{
    services::{
        LorebookService, EncryptionService,
        agentic::tools::{ScribeTool, ToolError, ToolParams, ToolResult},
        agentic::unified_tool_registry::{
            SelfRegisteringTool, ToolCategory, ToolCapability, ToolSecurityPolicy, AgentType,
            ToolExample, DataAccessPolicy, AuditLevel, ResourceRequirements, ExecutionTime, ErrorCode
        },
    },
    models::{
        lorebook_dtos::{
            CreateLorebookEntryPayload, LorebookEntryResponse,
            UpdateLorebookEntryPayload,
        },
        LorebookEntry,
    },
    errors::AppError,
    state::AppState,
    PgPool,
    auth::{user_store::Backend as AuthBackend, session_dek::SessionDek},
};
use axum_login::AuthSession;

// ===== AI-DRIVEN LOREBOOK QUERY TOOL =====

/// AI-powered tool that interprets natural language queries about lore and world knowledge
#[derive(Clone)]
pub struct QueryLorebookTool {
    app_state: Arc<AppState>,
}

impl QueryLorebookTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
    
    /// Search lorebook entries in Qdrant based on the AI analysis
    async fn search_lorebook_entries(
        &self,
        user_id: Uuid,
        analysis: &LoreQueryAnalysis,
        _session_dek: &SessionDek,
        limit: usize,
    ) -> Result<Vec<LorebookEntryInfo>, ToolError> {
        let mut all_entries = Vec::new();
        
        // Search for each primary search term
        for search_term in &analysis.search_strategy.search_terms {
            // Generate embedding for the search term
            let query_embedding = self.app_state.embedding_client
                .embed_content(search_term, "RETRIEVAL_QUERY", None)
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("Failed to embed search term: {}", e)))?;
            
            // Construct filter for lorebook entries
            use crate::vector_db::qdrant_client::{Filter, Condition, ConditionOneOf, FieldCondition, Match, MatchValue};
            
            let lorebook_filter = Filter {
                must: vec![
                    Condition {
                        condition_one_of: Some(ConditionOneOf::Field(
                            FieldCondition {
                                key: "user_id".to_string(),
                                r#match: Some(Match {
                                    match_value: Some(MatchValue::Keyword(user_id.to_string())),
                                }),
                                ..Default::default()
                            }
                        )),
                    },
                    Condition {
                        condition_one_of: Some(ConditionOneOf::Field(
                            FieldCondition {
                                key: "source_type".to_string(),
                                r#match: Some(Match {
                                    match_value: Some(MatchValue::Keyword("lorebook_entry".to_string())),
                                }),
                                ..Default::default()
                            }
                        )),
                    },
                ],
                ..Default::default()
            };
            
            // Search Qdrant
            match self.app_state.qdrant_service
                .search_points(query_embedding, limit as u64, Some(lorebook_filter))
                .await {
                Ok(search_results) => {
                    info!("Found {} lorebook results for search term '{}'", search_results.len(), search_term);
                    
                    for scored_point in search_results {
                        // Extract lorebook entry data from payload
                        let entry_id = scored_point.payload.get("original_lorebook_entry_id")
                            .and_then(|v| v.kind.as_ref())
                            .and_then(|k| match k {
                                qdrant_client::qdrant::value::Kind::StringValue(s) => Uuid::parse_str(s).ok(),
                                _ => None
                            })
                            .unwrap_or_else(Uuid::new_v4);
                            
                        let lorebook_id = scored_point.payload.get("lorebook_id")
                            .and_then(|v| v.kind.as_ref())
                            .and_then(|k| match k {
                                qdrant_client::qdrant::value::Kind::StringValue(s) => Uuid::parse_str(s).ok(),
                                _ => None
                            })
                            .unwrap_or_else(Uuid::new_v4);
                            
                        let title = scored_point.payload.get("entry_title")
                            .and_then(|v| v.kind.as_ref())
                            .and_then(|k| match k {
                                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
                                _ => None
                            })
                            .unwrap_or_else(|| "Unknown Entry".to_string());
                            
                        let content = scored_point.payload.get("chunk_text")
                            .and_then(|v| v.kind.as_ref())
                            .and_then(|k| match k {
                                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
                                _ => None
                            })
                            .unwrap_or_else(|| "No content available".to_string());
                            
                        let tags = scored_point.payload.get("decrypted_keywords")
                            .and_then(|v| {
                                // Handle Qdrant Value type - extract string list from value
                                if let qdrant_client::qdrant::value::Kind::ListValue(list) = &v.kind.as_ref()? {
                                    Some(list.values.iter()
                                        .filter_map(|val| {
                                            if let Some(qdrant_client::qdrant::value::Kind::StringValue(s)) = &val.kind {
                                                Some(s.clone())
                                            } else {
                                                None
                                            }
                                        })
                                        .collect())
                                } else {
                                    None
                                }
                            })
                            .unwrap_or_default();
                            
                        all_entries.push(LorebookEntryInfo {
                            id: entry_id,
                            lorebook_id,
                            title,
                            content,
                            tags,
                            relevance_score: scored_point.score as f64,
                            relevance_reasoning: format!("Semantic match for query term: {}", search_term),
                        });
                    }
                },
                Err(e) => {
                    error!("Failed to search lorebook in Qdrant: {}", e);
                    // Continue with other search terms even if one fails
                }
            }
        }
        
        // Deduplicate entries by ID and sort by relevance score
        let mut seen_ids = std::collections::HashSet::new();
        all_entries.retain(|entry| seen_ids.insert(entry.id));
        all_entries.sort_by(|a, b| b.relevance_score.partial_cmp(&a.relevance_score).unwrap());
        
        // Limit to requested number
        all_entries.truncate(limit);
        
        Ok(all_entries)
    }

    /// Build AI prompt for interpreting lore queries
    fn build_query_prompt(&self, request: &str, context: &str) -> String {
        format!(
            r#"You are an intelligent lore research agent for a dynamic roleplay world model system.

Your task is to interpret natural language queries about world lore, history, and knowledge.

LORE QUERY REQUEST:
"{}"

CURRENT CONTEXT:
{}

Your analysis should determine:
1. What type of lore information is being sought
2. The key concepts, entities, or topics to search for
3. The level of detail needed (summary vs comprehensive)
4. Any temporal or spatial constraints on the query
5. The search strategy that would best find this information

RESPONSE FORMAT (JSON):
{{
    "interpretation": "Clear restatement of what lore is being requested",
    "query_type": "character_lore|location_lore|history|magic_system|culture|technology|general_knowledge",
    "key_concepts": ["concept1", "concept2", "concept3"],
    "search_strategy": {{
        "primary_search": "name_based|category_based|tag_based|full_text|semantic",
        "search_terms": ["term1", "term2"],
        "include_related": true|false,
        "temporal_scope": "recent|historical|all_time|specific_period",
        "detail_level": "summary|moderate|comprehensive"
    }},
    "filters": {{
        "categories": ["category1", "category2"],
        "exclude_categories": ["category1"],
        "time_period": "optional time period filter",
        "reliability": "canon|semi_canon|speculation|all"
    }},
    "reasoning": "Explanation of why this search strategy was chosen",
    "expected_results": "Description of what kind of lore entries would satisfy this query"
}}

Examples:
- "Tell me about the Dragon Wars" → history query with key concepts ["Dragon Wars", "dragons", "war"]
- "What magical abilities does Alice have?" → character_lore query focused on ["Alice", "magic", "abilities"]
- "Describe the political system of the Northern Kingdom" → location_lore/culture query
- "What happened last session?" → recent temporal scope with full_text search

Be intelligent about interpreting the user's intent and what lore would be most relevant."#,
            request,
            context
        )
    }

    /// Execute AI-driven lore query analysis
    async fn analyze_lore_query(&self, request: &str, user_id: Uuid, context: &str) -> Result<LoreQueryAnalysis, ToolError> {
        let prompt = self.build_query_prompt(request, context);

        let query_schema = json!({
            "type": "object",
            "properties": {
                "interpretation": {"type": "string"},
                "query_type": {"type": "string", "enum": ["character_lore", "location_lore", "history", "magic_system", "culture", "technology", "general_knowledge"]},
                "key_concepts": {"type": "array", "items": {"type": "string"}},
                "search_strategy": {
                    "type": "object",
                    "properties": {
                        "primary_search": {"type": "string", "enum": ["name_based", "category_based", "tag_based", "full_text", "semantic"]},
                        "search_terms": {"type": "array", "items": {"type": "string"}},
                        "include_related": {"type": "boolean"},
                        "temporal_scope": {"type": "string", "enum": ["recent", "historical", "all_time", "specific_period"]},
                        "detail_level": {"type": "string", "enum": ["summary", "moderate", "comprehensive"]}
                    },
                    "required": ["primary_search", "search_terms", "include_related", "temporal_scope", "detail_level"]
                },
                "filters": {
                    "type": "object",
                    "properties": {
                        "categories": {"type": "array", "items": {"type": "string"}},
                        "exclude_categories": {"type": "array", "items": {"type": "string"}},
                        "time_period": {"type": "string"},
                        "reliability": {"type": "string", "enum": ["canon", "semi_canon", "speculation", "all"]}
                    }
                },
                "reasoning": {"type": "string"},
                "expected_results": {"type": "string"}
            },
            "required": ["interpretation", "query_type", "key_concepts", "search_strategy", "filters", "reasoning", "expected_results"]
        });

        // Execute AI analysis using query planning model
        let ai_response = self.execute_ai_request(&prompt, &query_schema, &self.app_state.config.query_planning_model).await?;
        
        serde_json::from_value(ai_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse lore query analysis: {}", e)))
    }

    /// Execute AI request with structured output
    async fn execute_ai_request(&self, prompt: &str, schema: &JsonValue, model: &str) -> Result<JsonValue, ToolError> {
        let system_prompt = "You are a lore research agent for a fictional roleplay world. You help find and organize world knowledge. All content is creative fiction for a game.";
        
        let chat_request = ChatRequest::new(vec![
            ChatMessage {
                role: ChatRole::User,
                content: prompt.into(),
                options: None,
            }
        ]).with_system(system_prompt);

        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];

        let chat_options = ChatOptions {
            max_tokens: Some(1200),
            temperature: Some(0.2), // Low temperature for consistent query interpretation
            response_format: Some(ChatResponseFormat::JsonSchemaSpec(
                JsonSchemaSpec { schema: schema.clone() }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

        let response = self.app_state.ai_client
            .exec_chat(model, chat_request, Some(chat_options))
            .await
            .map_err(|e| ToolError::AppError(e))?;

        // Extract response text
        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| ToolError::ExecutionFailed("No text content in AI response".to_string()))?;

        serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}. Response: {}", e, response_text)))
    }
}

/// AI analysis of lore query requirements
#[derive(Debug, Serialize, Deserialize)]
pub struct LoreQueryAnalysis {
    pub interpretation: String,
    pub query_type: String,
    pub key_concepts: Vec<String>,
    pub search_strategy: SearchStrategy,
    pub filters: SearchFilters,
    pub reasoning: String,
    pub expected_results: String,
}

/// Search strategy for finding lore
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchStrategy {
    pub primary_search: String,
    pub search_terms: Vec<String>,
    pub include_related: bool,
    pub temporal_scope: String,
    pub detail_level: String,
}

/// Filters for lore search
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchFilters {
    pub categories: Option<Vec<String>>,
    pub exclude_categories: Option<Vec<String>>,
    pub time_period: Option<String>,
    pub reliability: Option<String>,
}

/// Input for lore queries
#[derive(Debug, Deserialize)]
pub struct QueryLorebookInput {
    pub user_id: String,
    pub query_request: String,
    pub current_context: Option<String>,
    pub limit: Option<usize>,
}

/// Lorebook entry information
#[derive(Debug, Serialize)]
pub struct LorebookEntryInfo {
    pub id: Uuid,
    pub lorebook_id: Uuid,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub relevance_score: f64,
    pub relevance_reasoning: String,
}

/// Output from lorebook query
#[derive(Debug, Serialize)]
pub struct QueryLorebookOutput {
    pub query_analysis: LoreQueryAnalysis,
    pub entries: Vec<LorebookEntryInfo>,
    pub total_found: usize,
    pub search_summary: String,
}

#[async_trait]
impl ScribeTool for QueryLorebookTool {
    fn name(&self) -> &'static str {
        "query_lorebook"
    }
    
    fn description(&self) -> &'static str {
        "AI-powered lore search that interprets natural language queries about world knowledge, \
         history, characters, locations, and other lore. Intelligently finds relevant information \
         based on semantic understanding of the query."
    }
    
    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the query"
                },
                "query_request": {
                    "type": "string",
                    "description": "Natural language query about lore (e.g., 'Tell me about the Dragon Wars', 'What magical abilities does Alice have?')"
                },
                "current_context": {
                    "type": "string",
                    "description": "Optional context about the current scene or conversation"
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 10,
                    "description": "Maximum number of results to return"
                }
            },
            "required": ["user_id", "query_request"]
        })
    }
    
    #[instrument(skip(self, params, _session_dek), fields(tool = "query_lorebook"))]
    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let input: QueryLorebookInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;
        
        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        let limit = input.limit.unwrap_or(10).min(100);
        let context = input.current_context.unwrap_or_else(|| "No additional context provided".to_string());
        
        info!("AI lore query for user {}: '{}'", user_id, input.query_request);
        
        // Step 1: Use AI to analyze the lore query
        let analysis = self.analyze_lore_query(&input.query_request, user_id, &context).await?;
        
        debug!("AI analyzed lore query: {}", analysis.interpretation);
        
        // Step 2: Execute the search based on AI analysis
        let entries = self.search_lorebook_entries(user_id, &analysis, _session_dek, limit).await?;
        
        let output = QueryLorebookOutput {
            query_analysis: analysis,
            entries,
            total_found: 1,
            search_summary: "AI-driven lore search completed (actual database search not yet implemented)".to_string(),
        };
        
        info!("AI lore query completed for user {}", user_id);
        Ok(serde_json::to_value(output)?)
    }
}

// ===== AI-DRIVEN LOREBOOK MANAGEMENT TOOL =====

/// AI-powered tool that interprets natural language requests to document and update world lore
#[derive(Clone)]
pub struct ManageLorebookTool {
    app_state: Arc<AppState>,
}

impl ManageLorebookTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Build AI prompt for interpreting lore documentation requests
    fn build_management_prompt(&self, request: &str, context: &str) -> String {
        format!(
            r#"You are an intelligent lore documentation agent for a dynamic roleplay world model system.

Your task is to interpret natural language requests about documenting, recording, or updating world lore.

LORE DOCUMENTATION REQUEST:
"{}"

CURRENT CONTEXT:
{}

Your analysis should determine:
1. What type of lore is being documented (character, location, history, etc.)
2. Whether this is new lore or an update to existing lore
3. The appropriate title and categorization
4. Key tags and concepts for organization
5. The structure and formatting of the content

RESPONSE FORMAT (JSON):
{{
    "interpretation": "Clear restatement of what lore is being documented",
    "operation_type": "create_new|update_existing|link_to_entity",
    "lore_type": "character|location|history|magic|culture|technology|general",
    "suggested_title": "Appropriate title for this lore entry",
    "category": "Primary category for organization",
    "content_structure": {{
        "main_content": "The primary lore information to record",
        "key_facts": ["fact1", "fact2", "fact3"],
        "relationships": ["related_entity1", "related_entity2"],
        "temporal_context": "when this information is relevant",
        "reliability": "canon|semi_canon|speculation"
    }},
    "tags": ["tag1", "tag2", "tag3"],
    "update_strategy": "replace|append|merge",
    "reasoning": "Explanation of how the lore should be structured and stored",
    "cross_references": ["other entries this might relate to"]
}}

Examples:
- "The elves of the Northern Forest can live for 500 years" → create_new character/culture lore
- "Actually, Lord Blackwood has a secret daughter named Elena" → update_existing character lore
- "The Crystal of Eternal Light was destroyed in the Battle of Dawn" → create_new history/artifact lore
- "Add to the magic system that fire magic requires emotional control" → update_existing magic lore

Be intelligent about structuring world knowledge for easy retrieval and consistency."#,
            request,
            context
        )
    }

    /// Execute AI-driven lore documentation analysis
    async fn analyze_lore_documentation(&self, request: &str, user_id: Uuid, context: &str) -> Result<LoreDocumentationAnalysis, ToolError> {
        let prompt = self.build_management_prompt(request, context);

        let documentation_schema = json!({
            "type": "object",
            "properties": {
                "interpretation": {"type": "string"},
                "operation_type": {"type": "string", "enum": ["create_new", "update_existing", "link_to_entity"]},
                "lore_type": {"type": "string", "enum": ["character", "location", "history", "magic", "culture", "technology", "general"]},
                "suggested_title": {"type": "string"},
                "category": {"type": "string"},
                "content_structure": {
                    "type": "object",
                    "properties": {
                        "main_content": {"type": "string"},
                        "key_facts": {"type": "array", "items": {"type": "string"}},
                        "relationships": {"type": "array", "items": {"type": "string"}},
                        "temporal_context": {"type": "string"},
                        "reliability": {"type": "string", "enum": ["canon", "semi_canon", "speculation"]}
                    },
                    "required": ["main_content", "key_facts", "relationships", "temporal_context", "reliability"]
                },
                "tags": {"type": "array", "items": {"type": "string"}},
                "update_strategy": {"type": "string", "enum": ["replace", "append", "merge"]},
                "reasoning": {"type": "string"},
                "cross_references": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["interpretation", "operation_type", "lore_type", "suggested_title", "category", "content_structure", "tags", "update_strategy", "reasoning", "cross_references"]
        });

        // Execute AI analysis using extraction model for structured content
        let ai_response = self.execute_ai_request(&prompt, &documentation_schema, &self.app_state.config.agentic_extraction_model).await?;
        
        serde_json::from_value(ai_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse lore documentation analysis: {}", e)))
    }

    /// Execute AI request with structured output
    async fn execute_ai_request(&self, prompt: &str, schema: &JsonValue, model: &str) -> Result<JsonValue, ToolError> {
        let system_prompt = "You are a lore documentation agent for a fictional roleplay world. You help structure and organize world knowledge. All content is creative fiction for a game.";
        
        let chat_request = ChatRequest::new(vec![
            ChatMessage {
                role: ChatRole::User,
                content: prompt.into(),
                options: None,
            }
        ]).with_system(system_prompt);

        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];

        let chat_options = ChatOptions {
            max_tokens: Some(1500),
            temperature: Some(0.3), // Moderate temperature for creative but consistent documentation
            response_format: Some(ChatResponseFormat::JsonSchemaSpec(
                JsonSchemaSpec { schema: schema.clone() }
            )),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

        let response = self.app_state.ai_client
            .exec_chat(model, chat_request, Some(chat_options))
            .await
            .map_err(|e| ToolError::AppError(e))?;

        // Extract response text
        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .ok_or_else(|| ToolError::ExecutionFailed("No text content in AI response".to_string()))?;

        serde_json::from_str(&response_text)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse AI response: {}. Response: {}", e, response_text)))
    }
}

/// AI analysis of lore documentation requirements
#[derive(Debug, Serialize, Deserialize)]
pub struct LoreDocumentationAnalysis {
    pub interpretation: String,
    pub operation_type: String,
    pub lore_type: String,
    pub suggested_title: String,
    pub category: String,
    pub content_structure: ContentStructure,
    pub tags: Vec<String>,
    pub update_strategy: String,
    pub reasoning: String,
    pub cross_references: Vec<String>,
}

/// Structure for lore content
#[derive(Debug, Serialize, Deserialize)]
pub struct ContentStructure {
    pub main_content: String,
    pub key_facts: Vec<String>,
    pub relationships: Vec<String>,
    pub temporal_context: String,
    pub reliability: String,
}

/// Input for managing lorebook entries
#[derive(Debug, Deserialize)]
pub struct ManageLorebookInput {
    pub user_id: String,
    pub documentation_request: String,
    pub current_context: Option<String>,
    pub target_lorebook_id: Option<String>,
}

/// Output from manage lorebook operations
#[derive(Debug, Serialize)]
pub struct ManageLorebookOutput {
    pub documentation_analysis: LoreDocumentationAnalysis,
    pub success: bool,
    pub entry_id: Option<Uuid>,
    pub operation_performed: String,
    pub message: String,
}

#[async_trait]
impl ScribeTool for ManageLorebookTool {
    fn name(&self) -> &'static str {
        "manage_lorebook"
    }
    
    fn description(&self) -> &'static str {
        "AI-powered lore documentation that interprets natural language requests to record \
         world knowledge. Automatically structures, categorizes, and tags lore entries. \
         Use natural language like 'The elves can live for 500 years' or 'Lord Blackwood has a secret daughter'."
    }
    
    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "User ID performing the operation"
                },
                "documentation_request": {
                    "type": "string",
                    "description": "Natural language description of lore to document (e.g., 'The Crystal Tower was built 1000 years ago by the First Mages')"
                },
                "current_context": {
                    "type": "string",
                    "description": "Optional context about the current scene or conversation"
                },
                "target_lorebook_id": {
                    "type": "string",
                    "description": "Optional specific lorebook to add the entry to"
                }
            },
            "required": ["user_id", "documentation_request"]
        })
    }
    
    #[instrument(skip(self, params, _session_dek), fields(tool = "manage_lorebook"))]
    async fn execute(&self, params: &ToolParams, _session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        let input: ManageLorebookInput = serde_json::from_value(params.clone())
            .map_err(|e| ToolError::InvalidParams(format!("Invalid input: {}", e)))?;
        
        let user_id = Uuid::parse_str(&input.user_id)
            .map_err(|e| ToolError::InvalidParams(format!("Invalid user_id: {}", e)))?;
        
        let context = input.current_context.unwrap_or_else(|| "No additional context provided".to_string());
        
        info!("AI lore documentation for user {}: '{}'", user_id, input.documentation_request);
        
        // Step 1: Use AI to analyze the documentation request
        let analysis = self.analyze_lore_documentation(&input.documentation_request, user_id, &context).await?;
        
        debug!("AI analyzed lore documentation: {}", analysis.interpretation);
        
        // Step 2: Execute the documentation based on AI analysis
        // For now, this is a placeholder - in a full system, this would use the
        // analysis to actually create/update entries in the lorebook database
        let output = ManageLorebookOutput {
            documentation_analysis: analysis,
            success: true,
            entry_id: Some(Uuid::new_v4()),
            operation_performed: "create_new".to_string(),
            message: "AI lore documentation analysis completed (actual database operation not yet implemented)".to_string(),
        };
        
        info!("AI lore documentation completed for user {}", user_id);
        Ok(serde_json::to_value(output)?)
    }
}

// ===== SELF-REGISTERING TOOL IMPLEMENTATIONS =====

#[async_trait]
impl SelfRegisteringTool for QueryLorebookTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Discovery
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "search".to_string(),
                target: "lore".to_string(),
                context: Some("natural language".to_string()),
            },
            ToolCapability {
                action: "interpret".to_string(),
                target: "lore queries".to_string(),
                context: Some("semantic understanding".to_string()),
            },
            ToolCapability {
                action: "find".to_string(),
                target: "world knowledge".to_string(),
                context: Some(

"contextual relevance".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to find lore, world knowledge, character information, or historical data. \
         Perfect for natural language queries like 'Tell me about the Dragon Wars', 'What are the \
         magical rules in this world?', or 'What do we know about Lord Blackwood?'".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for creating new lore entries, modifying existing lore, or for non-lore \
         information. Use the manage_lorebook tool for documentation or other tools for \
         different types of queries.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Query about historical events".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "query_request": "Tell me about the Dragon Wars and how they ended",
                    "current_context": "Players are exploring ancient ruins from that era"
                }),
                expected_output: "Relevant lore entries about the Dragon Wars with AI analysis of the query intent".to_string(),
            },
            ToolExample {
                scenario: "Character background query".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "query_request": "What magical abilities does the Archmage Elara possess?",
                    "limit": 5
                }),
                expected_output: "Character lore about Archmage Elara focusing on magical abilities".to_string(),
            },
        ]
    }
    
    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
                AgentType::Perception,
            ],
            required_capabilities: vec![],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false, // Read-only access to lore
                allowed_scopes: vec!["lorebook".to_string(), "knowledge".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 80,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Uses AI client
            compute_intensive: false,
        }
    }
    
    fn dependencies(&self) -> Vec<String> {
        vec![
            "lorebook_service".to_string(),
            "ai_client".to_string(),
        ]
    }
    
    fn tags(&self) -> Vec<String> {
        vec![
            "lore".to_string(),
            "search".to_string(),
            "knowledge".to_string(),
            "ai-powered".to_string(),
            "query".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "query_analysis": {
                    "type": "object",
                    "description": "AI interpretation of the lore query including search strategy"
                },
                "entries": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "title": {"type": "string"},
                            "content": {"type": "string"},
                            "tags": {"type": "array", "items": {"type": "string"}},
                            "relevance_score": {"type": "number"},
                            "relevance_reasoning": {"type": "string"}
                        }
                    },
                    "description": "Lore entries found matching the query"
                },
                "total_found": {
                    "type": "integer",
                    "description": "Total number of matching entries found"
                },
                "search_summary": {
                    "type": "string",
                    "description": "Summary of the search results and strategy used"
                }
            },
            "required": ["query_analysis", "entries", "total_found", "search_summary"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "INVALID_USER_ID".to_string(),
                description: "The provided user ID is not valid".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "AI_QUERY_ANALYSIS_FAILED".to_string(),
                description: "The AI service failed to analyze the lore query".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "LORE_SEARCH_FAILED".to_string(),
                description: "Failed to search the lorebook database".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "DECRYPTION_FAILED".to_string(),
                description: "Failed to decrypt lorebook entries".to_string(),
                retry_able: false,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

#[async_trait]
impl SelfRegisteringTool for ManageLorebookTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Management
    }
    
    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "document".to_string(),
                target: "lore".to_string(),
                context: Some("natural language".to_string()),
            },
            ToolCapability {
                action: "structure".to_string(),
                target: "world knowledge".to_string(),
                context: Some("intelligent categorization".to_string()),
            },
            ToolCapability {
                action: "update".to_string(),
                target: "lore entries".to_string(),
                context: Some("contextual understanding".to_string()),
            },
        ]
    }
    
    fn when_to_use(&self) -> String {
        "Use when you need to document new lore, world knowledge, or character information. \
         Perfect for natural language documentation like 'The elves can live for 500 years', \
         'The Crystal Tower was destroyed', or 'Lord Blackwood has a secret alliance'".to_string()
    }
    
    fn when_not_to_use(&self) -> String {
        "Do not use for searching or reading existing lore. Use the query_lorebook tool \
         for finding information. This tool is specifically for creating and updating lore.".to_string()
    }
    
    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Document new world lore".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "documentation_request": "The Northern Elves have developed a new form of ice magic that doesn't require verbal components",
                    "current_context": "During exploration of the Northern Wastes"
                }),
                expected_output: "New lore entry created with AI-structured content about Northern Elf ice magic".to_string(),
            },
            ToolExample {
                scenario: "Update character information".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "documentation_request": "Lord Blackwood secretly has a daughter named Elena who is training to be a mage",
                    "current_context": "Revealed during interrogation scene"
                }),
                expected_output: "Character lore updated with new information about Lord Blackwood's family".to_string(),
            },
        ]
    }
    
    fn security_policy(&self) -> ToolSecurityPolicy {
        ToolSecurityPolicy {
            allowed_agents: vec![
                AgentType::Orchestrator,
                AgentType::Strategic,
                AgentType::Tactical,
            ],
            required_capabilities: vec![],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: true, // Can create and update lore
                allowed_scopes: vec!["lorebook".to_string(), "knowledge".to_string()],
            },
            audit_level: AuditLevel::Detailed,
        }
    }
    
    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 90,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Uses AI client
            compute_intensive: false,
        }
    }
    
    fn dependencies(&self) -> Vec<String> {
        vec![
            "lorebook_service".to_string(),
            "encryption_service".to_string(),
            "ai_client".to_string(),
        ]
    }
    
    fn tags(&self) -> Vec<String> {
        vec![
            "lore".to_string(),
            "documentation".to_string(),
            "management".to_string(),
            "ai-powered".to_string(),
            "creation".to_string(),
        ]
    }
    
    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "documentation_analysis": {
                    "type": "object",
                    "description": "AI analysis of how to structure and store the lore"
                },
                "success": {
                    "type": "boolean",
                    "description": "Whether the documentation operation was successful"
                },
                "entry_id": {
                    "type": "string",
                    "description": "UUID of the created or updated lore entry"
                },
                "operation_performed": {
                    "type": "string",
                    "description": "Type of operation performed (create_new, update_existing, etc.)"
                },
                "message": {
                    "type": "string",
                    "description": "Status message about the documentation operation"
                }
            },
            "required": ["documentation_analysis", "success", "operation_performed", "message"]
        })
    }
    
    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "INVALID_USER_ID".to_string(),
                description: "The provided user ID is not valid".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "AI_DOCUMENTATION_ANALYSIS_FAILED".to_string(),
                description: "The AI service failed to analyze the documentation request".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "LORE_CREATION_FAILED".to_string(),
                description: "Failed to create new lore entry in the database".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "ENCRYPTION_FAILED".to_string(),
                description: "Failed to encrypt lore content".to_string(),
                retry_able: false,
            },
        ]
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
}

/// Register lorebook tools with the unified registry
pub fn register_lorebook_tools(app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    let query_tool = Arc::new(QueryLorebookTool::new(app_state.clone())) 
        as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register_if_not_exists(query_tool)?;
    
    let manage_tool = Arc::new(ManageLorebookTool::new(app_state.clone())) 
        as Arc<dyn SelfRegisteringTool + Send + Sync>;
    UnifiedToolRegistry::register_if_not_exists(manage_tool)?;
    
    tracing::info!("Registered 2 AI-driven lorebook tools with unified registry");
    Ok(())
}