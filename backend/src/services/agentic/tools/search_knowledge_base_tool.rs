//! AI-Powered Knowledge Base Search Tool
//!
//! This tool provides intelligent search across all knowledge sources:
//! chronicles, lorebook entries, and entities using AI-enhanced queries.

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

/// Self-registering tool for AI-powered knowledge base search
pub struct SearchKnowledgeBaseTool {
    app_state: Arc<AppState>,
}

impl SearchKnowledgeBaseTool {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }
}

#[async_trait]
impl ScribeTool for SearchKnowledgeBaseTool {
    fn name(&self) -> &'static str {
        "search_knowledge_base"
    }

    fn description(&self) -> &'static str {
        "AI-powered search across all knowledge sources (chronicles, lorebook, entities). Uses intelligent query interpretation and semantic ranking to find relevant information."
    }

    fn input_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "user_id": {
                    "type": "string",
                    "description": "The UUID of the user performing the search"
                },
                "query": {
                    "type": "string",
                    "description": "The search query in natural language"
                },
                "sources": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["chronicles", "lorebook", "entities", "all"]},
                    "description": "Which knowledge sources to search (default: all)"
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "description": "Maximum number of results to return (default: 10)"
                },
                "context": {
                    "type": "string",
                    "description": "Optional additional context to help interpret the query"
                }
            },
            "required": ["user_id", "query"]
        })
    }

    async fn execute(&self, params: &ToolParams, session_dek: &SessionDek) -> Result<ToolResult, ToolError> {
        debug!("Executing search_knowledge_base tool with AI-enhanced search");

        let user_id_str = params.get("user_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("user_id is required".to_string()))?;

        let query = params.get("query")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::InvalidParams("query is required".to_string()))?;

        let sources = params.get("sources")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_else(|| vec!["all"]);

        let limit = params.get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;

        let context = params.get("context")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let user_id = Uuid::parse_str(user_id_str)
            .map_err(|_| ToolError::InvalidParams("Invalid user_id format".to_string()))?;

        info!("Searching knowledge base for user {} with query: '{}'", user_id, query);

        // Step 1: Use Flash to analyze and enhance the query
        let query_analysis = self.analyze_search_query(query, context, &sources).await?;

        // Step 2: Search different knowledge sources based on analysis
        let mut all_results = Vec::new();

        if sources.contains(&"all") || sources.contains(&"chronicles") {
            if let Ok(chronicle_results) = self.search_chronicles(user_id, &query_analysis, session_dek).await {
                all_results.extend(chronicle_results);
            }
        }

        if sources.contains(&"all") || sources.contains(&"lorebook") {
            if let Ok(lorebook_results) = self.search_lorebook(user_id, &query_analysis, session_dek).await {
                all_results.extend(lorebook_results);
            }
        }

        if sources.contains(&"all") || sources.contains(&"entities") {
            if let Ok(entity_results) = self.search_entities(user_id, &query_analysis).await {
                all_results.extend(entity_results);
            }
        }

        // Step 3: Use Flash to rank and filter results by relevance
        let ranked_results = self.rank_search_results(query, &all_results, limit).await?;

        info!("Knowledge base search completed for user {}, found {} results", 
              user_id, ranked_results.len());

        Ok(json!({
            "status": "success",
            "query": query,
            "query_analysis": query_analysis,
            "sources_searched": sources,
            "results": ranked_results,
            "total_found": all_results.len(),
            "results_returned": ranked_results.len(),
            "search_metadata": {
                "user_id": user_id,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "model_used": self.app_state.config.fast_model
            }
        }))
    }

    // Private helper methods would be implemented here...
}

impl SearchKnowledgeBaseTool {
    /// Analyze search query using Flash AI to enhance search strategy
    async fn analyze_search_query(
        &self, 
        query: &str, 
        context: &str, 
        sources: &[&str]
    ) -> Result<JsonValue, ToolError> {
        let analysis_prompt = format!(
            r#"Analyze this search query and determine the best search strategy across different knowledge sources.

SEARCH QUERY: "{}"

CONTEXT: {}

AVAILABLE SOURCES: {:?}

ANALYSIS INSTRUCTIONS:
- Identify the main intent and type of information being sought
- Extract key concepts, entities, and search terms
- Determine temporal scope (recent, historical, all-time)
- Classify the information type (factual, narrative, relationships, etc.)
- Suggest search strategies for each source type
- Identify potential synonyms or related terms

RESPOND WITH JSON:
{{
    "query_intent": "string (what the user is trying to find)",
    "information_type": "string (factual|narrative|relationships|events|entities|lore)",
    "key_concepts": ["string (important concepts to search for)"],
    "entities_mentioned": ["string (character/location/item names mentioned)"],
    "temporal_scope": "string (recent|historical|all_time|specific_period)",
    "search_terms": {{
        "primary": ["string (main search terms)"],
        "secondary": ["string (related/synonym terms)"],
        "exclude": ["string (terms to avoid)"]
    }},
    "source_strategies": {{
        "chronicles": {{
            "strategy": "string (how to search chronicles)",
            "filters": ["string (relevant filters)"]
        }},
        "lorebook": {{
            "strategy": "string (how to search lorebook)",
            "categories": ["string (relevant lorebook categories)"]
        }},
        "entities": {{
            "strategy": "string (how to search entities)",
            "entity_types": ["string (relevant entity types)"]
        }}
    }},
    "relevance_factors": ["string (factors that make results relevant)"],
    "analysis_method": "Flash AI query analysis"
}}"#,
            query, context, sources
        );

        // Define schema for structured output
        let schema = json!({
            "type": "object",
            "properties": {
                "query_intent": {"type": "string"},
                "information_type": {"type": "string"},
                "key_concepts": {"type": "array", "items": {"type": "string"}},
                "entities_mentioned": {"type": "array", "items": {"type": "string"}},
                "temporal_scope": {"type": "string"},
                "search_terms": {
                    "type": "object",
                    "properties": {
                        "primary": {"type": "array", "items": {"type": "string"}},
                        "secondary": {"type": "array", "items": {"type": "string"}},
                        "exclude": {"type": "array", "items": {"type": "string"}}
                    }
                },
                "source_strategies": {"type": "object"},
                "relevance_factors": {"type": "array", "items": {"type": "string"}},
                "analysis_method": {"type": "string"}
            },
            "required": ["query_intent", "information_type", "key_concepts", "analysis_method"]
        });

        use genai::chat::{ChatRequest, ChatOptions, ChatResponseFormat, JsonSchemaSpec};
        
        let chat_request = ChatRequest::from_user(analysis_prompt);
        let mut chat_options = ChatOptions::default()
            .with_max_tokens(1500)
            .with_temperature(0.3);
        
        chat_options = chat_options.with_response_format(
            ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec { schema })
        );
        
        let response = self.app_state.ai_client
            .exec_chat(
                &self.app_state.config.fast_model,
                chat_request,
                Some(chat_options),
            )
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Query analysis failed: {}", e)))?;
        
        let flash_response = response.first_content_text_as_str()
            .ok_or_else(|| ToolError::ExecutionFailed("Empty response from Flash".to_string()))?;

        serde_json::from_str(&flash_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse analysis: {}", e)))
    }

    /// Search chronicles using the chronicle service
    async fn search_chronicles(
        &self,
        user_id: Uuid,
        query_analysis: &JsonValue,
        session_dek: &SessionDek,
    ) -> Result<Vec<JsonValue>, ToolError> {
        let mut results = Vec::new();

        // Get user's chronicles
        let chronicles = self.app_state.chronicle_service
            .get_user_chronicles(user_id)
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get chronicles: {}", e)))?;

        // Search through chronicle events
        for chronicle in chronicles {
            let events = self.app_state.chronicle_service
                .get_chronicle_events(
                    user_id,
                    chronicle.id,
                    crate::models::chronicle_event::EventFilter::default()
                )
                .await
                .map_err(|e| ToolError::ExecutionFailed(format!("Failed to get events: {}", e)))?;

            for event in events {
                // Decrypt summary for searching
                let summary = if let (Some(encrypted_summary), Some(nonce)) = 
                    (&event.summary_encrypted, &event.summary_nonce) {
                    match crate::crypto::decrypt_gcm(encrypted_summary, nonce, &session_dek.0) {
                        Ok(decrypted_secret) => {
                            use secrecy::ExposeSecret;
                            String::from_utf8_lossy(decrypted_secret.expose_secret()).to_string()
                        },
                        Err(_) => event.summary.clone(),
                    }
                } else {
                    event.summary.clone()
                };

                results.push(json!({
                    "source": "chronicle",
                    "type": "event",
                    "id": event.id,
                    "chronicle_id": chronicle.id,
                    "title": summary.clone(),
                    "content": summary,
                    "event_type": event.event_type,
                    "timestamp": event.timestamp_iso8601,
                    "metadata": event.event_data
                }));
            }
        }

        Ok(results)
    }

    /// Search lorebook using the lorebook service
    async fn search_lorebook(
        &self,
        user_id: Uuid,
        _query_analysis: &JsonValue,
        _session_dek: &SessionDek,
    ) -> Result<Vec<JsonValue>, ToolError> {
        // The lorebook service requires auth session, which we don't have in tool context
        // For now, we'll use the existing QueryLorebookTool via the unified registry
        // This is a simplified search that returns basic lorebook info
        
        // TODO: Implement proper lorebook search integration
        // For now, return empty results as lorebook access requires auth session
        Ok(Vec::new())
    }

    /// Search entities using the ECS entity manager
    async fn search_entities(
        &self,
        user_id: Uuid,
        _query_analysis: &JsonValue,
    ) -> Result<Vec<JsonValue>, ToolError> {
        let mut results = Vec::new();

        // Use the entity manager to search entities using query_entities method
        let entity_results = self.app_state.ecs_entity_manager
            .query_entities(user_id, Vec::new(), Some(20), None) // No criteria, limit 20, no offset
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to query entities: {}", e)))?;

        for result in entity_results.into_iter().take(20) {
            let mut content_parts = Vec::new();
            
            // Extract readable content from components
            for component in &result.components {
                if let Some(description) = component.component_data.get("description").and_then(|v| v.as_str()) {
                    content_parts.push(format!("{}: {}", component.component_type, description));
                }
            }

            // Get component types list
            let component_types: Vec<String> = result.components.iter()
                .map(|c| c.component_type.clone())
                .collect();

            results.push(json!({
                "source": "entities",
                "type": "entity",
                "id": result.entity.id,
                "title": format!("Entity {}", result.entity.id),
                "content": content_parts.join(", "),
                "entity_type": "unknown", // Would need to determine from components
                "components": component_types
            }));
        }

        Ok(results)
    }

    /// Rank search results using Flash AI
    async fn rank_search_results(
        &self,
        original_query: &str,
        results: &[JsonValue],
        limit: usize,
    ) -> Result<Vec<JsonValue>, ToolError> {
        if results.is_empty() {
            return Ok(Vec::new());
        }

        // If we have fewer results than the limit, return all
        if results.len() <= limit {
            return Ok(results.to_vec());
        }

        // Use Flash to rank results by relevance
        let ranking_prompt = format!(
            r#"Rank these search results by relevance to the user's query.

ORIGINAL QUERY: "{}"

SEARCH RESULTS:
{}

RANKING INSTRUCTIONS:
- Assess how well each result answers or relates to the query
- Consider content relevance, recency, and information quality
- Rank from most relevant (1) to least relevant
- Return only the top {} results

RESPOND WITH JSON:
{{
    "ranked_results": [
        {{
            "result_index": number,
            "relevance_score": number (0.0-1.0),
            "relevance_reasoning": "string (why this result is relevant)"
        }}
    ],
    "ranking_method": "Flash AI relevance ranking"
}}"#,
            original_query,
            serde_json::to_string_pretty(results).unwrap_or_default(),
            limit
        );

        let schema = json!({
            "type": "object",
            "properties": {
                "ranked_results": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "result_index": {"type": "number"},
                            "relevance_score": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                            "relevance_reasoning": {"type": "string"}
                        },
                        "required": ["result_index", "relevance_score"]
                    }
                },
                "ranking_method": {"type": "string"}
            },
            "required": ["ranked_results"]
        });

        use genai::chat::{ChatRequest, ChatOptions, ChatResponseFormat, JsonSchemaSpec};
        
        let chat_request = ChatRequest::from_user(ranking_prompt);
        let mut chat_options = ChatOptions::default()
            .with_max_tokens(2000)
            .with_temperature(0.2);
        
        chat_options = chat_options.with_response_format(
            ChatResponseFormat::JsonSchemaSpec(JsonSchemaSpec { schema })
        );
        
        let response = self.app_state.ai_client
            .exec_chat(
                &self.app_state.config.fast_model,
                chat_request,
                Some(chat_options),
            )
            .await
            .map_err(|e| ToolError::ExecutionFailed(format!("Result ranking failed: {}", e)))?;
        
        let flash_response = response.first_content_text_as_str()
            .ok_or_else(|| ToolError::ExecutionFailed("Empty response from Flash".to_string()))?;

        let ranking: JsonValue = serde_json::from_str(&flash_response)
            .map_err(|e| ToolError::ExecutionFailed(format!("Failed to parse ranking: {}", e)))?;

        // Extract ranked results
        let mut ranked_results = Vec::new();
        if let Some(ranked_indices) = ranking.get("ranked_results").and_then(|r| r.as_array()) {
            for ranking_item in ranked_indices.iter().take(limit) {
                if let Some(index) = ranking_item.get("result_index").and_then(|i| i.as_u64()) {
                    if let Some(result) = results.get(index as usize) {
                        let mut enhanced_result = result.clone();
                        enhanced_result["relevance_score"] = ranking_item.get("relevance_score").cloned().unwrap_or(json!(0.5));
                        enhanced_result["relevance_reasoning"] = ranking_item.get("relevance_reasoning").cloned().unwrap_or(json!(""));
                        ranked_results.push(enhanced_result);
                    }
                }
            }
        }

        Ok(ranked_results)
    }
}

#[async_trait]
impl SelfRegisteringTool for SearchKnowledgeBaseTool {
    fn category(&self) -> ToolCategory {
        ToolCategory::Discovery
    }

    fn capabilities(&self) -> Vec<ToolCapability> {
        vec![
            ToolCapability {
                action: "search".to_string(),
                target: "knowledge base".to_string(),
                context: Some("across chronicles, lorebook, and entities".to_string()),
            },
            ToolCapability {
                action: "analyze".to_string(),
                target: "search queries".to_string(),
                context: Some("with AI-enhanced understanding".to_string()),
            },
            ToolCapability {
                action: "rank".to_string(),
                target: "search results".to_string(),
                context: Some("by relevance and quality".to_string()),
            },
        ]
    }

    fn when_to_use(&self) -> String {
        "Use this tool when you need to find existing information across all knowledge sources. Perfect for discovering past events, lore details, character information, or any previously recorded data. Uses AI to understand queries and rank results by relevance.".to_string()
    }

    fn when_not_to_use(&self) -> String {
        "Don't use for creating new content (use creation tools instead), for current real-time information, or when you need to modify existing data rather than just retrieve it.".to_string()
    }

    fn usage_examples(&self) -> Vec<ToolExample> {
        vec![
            ToolExample {
                scenario: "Searching for information about a character's past".to_string(),
                input: json!({
                    "user_id": "123e4567-e89b-12d3-a456-426614174000",
                    "query": "Sir Gareth dragon encounters previous battles",
                    "sources": ["all"],
                    "limit": 10
                }),
                expected_output: "Returns ranked search results from chronicles, lorebook, and entities with relevance scores".to_string(),
            }
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
            required_capabilities: vec!["search".to_string()],
            rate_limit: None,
            data_access: DataAccessPolicy {
                user_data: true,
                system_data: false,
                write_access: false, // Read-only search tool
                allowed_scopes: vec!["chronicles".to_string(), "lorebook".to_string(), "entities".to_string()],
            },
            audit_level: AuditLevel::Basic,
        }
    }

    fn resource_requirements(&self) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 150,
            execution_time: ExecutionTime::Moderate,
            external_calls: true, // Flash API calls for analysis and ranking
            compute_intensive: false,
        }
    }

    fn output_schema(&self) -> JsonValue {
        json!({
            "type": "object",
            "properties": {
                "status": {"type": "string"},
                "query": {"type": "string"},
                "query_analysis": {"type": "object"},
                "sources_searched": {"type": "array", "items": {"type": "string"}},
                "results": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "source": {"type": "string"},
                            "type": {"type": "string"},
                            "title": {"type": "string"},
                            "content": {"type": "string"},
                            "relevance_score": {"type": "number"},
                            "metadata": {"type": "object"}
                        }
                    }
                },
                "total_found": {"type": "integer"},
                "results_returned": {"type": "integer"},
                "search_metadata": {"type": "object"}
            },
            "required": ["status", "query", "results", "total_found"]
        })
    }

    fn tags(&self) -> Vec<String> {
        vec![
            "ai-powered".to_string(),
            "flash".to_string(),
            "search".to_string(),
            "knowledge-base".to_string(),
            "semantic".to_string(),
            "ranking".to_string(),
            "discovery".to_string(),
        ]
    }

    fn error_codes(&self) -> Vec<ErrorCode> {
        vec![
            ErrorCode {
                code: "NO_RESULTS_FOUND".to_string(),
                description: "No relevant results found across all searched sources".to_string(),
                retry_able: false,
            },
            ErrorCode {
                code: "SEARCH_FAILED".to_string(),
                description: "Failed to search one or more knowledge sources".to_string(),
                retry_able: true,
            },
            ErrorCode {
                code: "QUERY_ANALYSIS_FAILED".to_string(),
                description: "AI analysis of the search query failed".to_string(),
                retry_able: true,
            },
        ]
    }
}

/// Registration function for the tool
pub fn register_search_knowledge_base_tool(app_state: Arc<AppState>) -> Result<(), AppError> {
    use crate::services::agentic::unified_tool_registry::UnifiedToolRegistry;
    
    let tool = Arc::new(SearchKnowledgeBaseTool::new(app_state)) as Arc<dyn SelfRegisteringTool>;
    UnifiedToolRegistry::register_if_not_exists(tool)?;
    
    Ok(())
}