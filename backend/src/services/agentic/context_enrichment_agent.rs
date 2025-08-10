//! Lightweight context enrichment agent with full audit trail support
//!
//! This agent provides intelligent context retrieval for chat conversations,
//! operating in either pre-processing (before LLM response) or post-processing
//! (after LLM response) mode. All operations are fully auditable with encrypted
//! storage of the agent's reasoning and execution log.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};
use uuid::Uuid;
use genai::chat::{ChatMessage as GenAiChatMessage, ChatRole, MessageContent, ChatOptions, ChatRequest, ChatResponseFormat, JsonSchemaSpec};

use crate::{
    AppState,
    crypto,
    errors::AppError,
    services::{
        agentic::narrative_tools::SearchKnowledgeBaseTool,
        safety_utils::create_unrestricted_safety_settings,
        ChronicleService,
    },
};
use secrecy::SecretBox;

use super::tools::ScribeTool;

/// Mode of operation for the context enrichment agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrichmentMode {
    PreProcessing,  // Run before generating AI response
    PostProcessing, // Run after AI response is sent
}

/// Complete result of context enrichment including audit trail
#[derive(Debug, Serialize, Deserialize)]
pub struct ContextEnrichmentResult {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub mode: EnrichmentMode,
    pub agent_reasoning: String,
    pub planned_searches: Vec<PlannedSearch>,
    pub execution_log: AgentExecutionLog,
    pub retrieved_context: String,
    pub analysis_summary: String,
    pub total_tokens_used: u32,
    pub execution_time_ms: u64,
    pub model_used: String,
}

/// A search query planned by the agent
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PlannedSearch {
    pub query: String,
    pub reason: String,
    pub search_type: String, // "all", "chronicles", "lorebooks"
}

/// Complete execution log for auditability
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentExecutionLog {
    pub steps: Vec<AgentStep>,
    pub total_duration_ms: u64,
    pub model_used: String,
}

/// A single step in the agent's execution
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentStep {
    pub step_number: u32,
    pub timestamp: DateTime<Utc>,
    pub action_type: String, // "planning", "search", "synthesis"
    pub thought: String,
    pub tool_call: Option<ToolCall>,
    pub result: Option<Value>,
    pub tokens_used: u32,
    pub duration_ms: u64,
}

/// Record of a tool invocation
#[derive(Debug, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool_name: String,
    pub parameters: Value,
}

/// The lightweight context enrichment agent
pub struct ContextEnrichmentAgent {
    state: Arc<AppState>,
    search_tool: Arc<SearchKnowledgeBaseTool>,
    chronicle_service: Arc<ChronicleService>,
    model: String, // Flash-Lite for lightweight operation
}

impl ContextEnrichmentAgent {
    /// Create a new context enrichment agent
    pub fn new(
        state: Arc<AppState>,
        search_tool: Arc<SearchKnowledgeBaseTool>,
        chronicle_service: Arc<ChronicleService>,
    ) -> Self {
        Self {
            state,
            search_tool,
            chronicle_service,
            model: "gemini-2.5-flash-lite".to_string(), // Lightweight model for speed
        }
    }

    /// Main entry point: Enrich context for a chat session
    pub async fn enrich_context(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        messages: &[(String, String)], // (role, content) pairs
        mode: EnrichmentMode,
        session_dek: &[u8],
    ) -> Result<ContextEnrichmentResult, AppError> {
        let start_time = Instant::now();
        let mut execution_log = AgentExecutionLog {
            steps: Vec::new(),
            total_duration_ms: 0,
            model_used: self.model.clone(),
        };

        info!(
            "Starting context enrichment for session {} in {:?} mode",
            session_id, mode
        );

        // Step 1: Planning - Analyze conversation and plan searches
        let (agent_reasoning, planned_searches, planning_step) = 
            self.plan_searches(messages, mode).await?;
        execution_log.steps.push(planning_step);

        // Step 2: Execute searches
        let mut all_search_results = Vec::new();
        for search in &planned_searches {
            let step_start = Instant::now();
            
            match self.execute_search(search, user_id, None).await {
                Ok((results, tokens)) => {
                    all_search_results.push(results.clone());
                    
                    let search_step = AgentStep {
                        step_number: execution_log.steps.len() as u32 + 1,
                        timestamp: Utc::now(),
                        action_type: "search".to_string(),
                        thought: format!("Searching for '{}' because: {}", search.query, search.reason),
                        tool_call: Some(ToolCall {
                            tool_name: "search_knowledge_base".to_string(),
                            parameters: json!({
                                "query": search.query,
                                "search_type": search.search_type,
                                "limit": 10,
                                "user_id": user_id.to_string()  // SECURITY: Log user_id in audit trail
                            }),
                        }),
                        result: Some(results),
                        tokens_used: tokens,
                        duration_ms: step_start.elapsed().as_millis() as u64,
                    };
                    execution_log.steps.push(search_step);
                }
                Err(e) => {
                    warn!("Search failed for query '{}': {}", search.query, e);
                    // Log the failure but continue with other searches
                    let error_step = AgentStep {
                        step_number: execution_log.steps.len() as u32 + 1,
                        timestamp: Utc::now(),
                        action_type: "search_error".to_string(),
                        thought: format!("Search failed for '{}'", search.query),
                        tool_call: None,
                        result: Some(json!({"error": e.to_string()})),
                        tokens_used: 0,
                        duration_ms: step_start.elapsed().as_millis() as u64,
                    };
                    execution_log.steps.push(error_step);
                }
            }
        }

        // Step 3: Synthesize results into useful context
        let (retrieved_context, analysis_summary, synthesis_step) = 
            self.synthesize_results(&all_search_results, messages).await?;
        execution_log.steps.push(synthesis_step);

        // Calculate totals
        let total_tokens: u32 = execution_log.steps.iter().map(|s| s.tokens_used).sum();
        let execution_time_ms = start_time.elapsed().as_millis() as u64;
        execution_log.total_duration_ms = execution_time_ms;

        info!(
            "Context enrichment completed: {} tokens, {}ms, {} search results",
            total_tokens,
            execution_time_ms,
            all_search_results.len()
        );

        // Store the analysis for audit trail (encrypted)
        self.store_analysis(
            session_id,
            user_id,
            &agent_reasoning,
            &planned_searches,
            &execution_log,
            &retrieved_context,
            &analysis_summary,
            total_tokens,
            execution_time_ms,
            mode,
            session_dek,
        ).await?;

        Ok(ContextEnrichmentResult {
            session_id,
            user_id,
            mode,
            agent_reasoning,
            planned_searches,
            execution_log,
            retrieved_context,
            analysis_summary,
            total_tokens_used: total_tokens,
            execution_time_ms,
            model_used: self.model.clone(),
        })
    }

    /// Step 1: Plan what searches to execute based on the conversation
    async fn plan_searches(
        &self,
        messages: &[(String, String)],
        mode: EnrichmentMode,
    ) -> Result<(String, Vec<PlannedSearch>, AgentStep), AppError> {
        let step_start = Instant::now();
        
        // Build a focused prompt for the planning agent
        let user_message_content = self.build_planning_prompt(messages, mode);
        
        debug!("Planning searches with prompt length: {}", user_message_content.len());

        // Create structured output schema for planning
        let planning_schema = json!({
            "type": "object",
            "properties": {
                "reasoning": {
                    "type": "string",
                    "description": "Your analysis of what context would be helpful for this conversation"
                },
                "searches": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "The search keywords (2-4 words)"
                            },
                            "reason": {
                                "type": "string",
                                "description": "Why this search is needed"
                            },
                            "search_type": {
                                "type": "string",
                                "enum": ["all", "chronicles", "lorebooks"],
                                "description": "What to search in"
                            }
                        },
                        "required": ["query", "reason", "search_type"]
                    },
                    "minItems": 2,
                    "maxItems": 5,
                    "description": "List of searches to perform"
                }
            },
            "required": ["reasoning", "searches"]
        });

        // Create chat messages
        let user_message = GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text(user_message_content),
            options: None,
        };
        
        // Add a prefill to establish context
        let prefill_message = GenAiChatMessage {
            role: ChatRole::Assistant,
            content: MessageContent::Text(
                "I'll analyze this conversation and plan strategic searches to find relevant context:".to_string()
            ),
            options: None,
        };
        
        let messages_vec = vec![user_message, prefill_message];
        
        // Build chat options
        let mut chat_options = ChatOptions::default();
        chat_options = chat_options.with_temperature(0.7); // Some creativity for search planning
        chat_options = chat_options.with_max_tokens(1024); // Don't need much for planning
        
        // Enable structured output
        let json_schema_spec = JsonSchemaSpec::new(planning_schema.clone());
        let response_format = ChatResponseFormat::JsonSchemaSpec(json_schema_spec);
        chat_options = chat_options.with_response_format(response_format);
        
        // Add safety settings
        let safety_settings = create_unrestricted_safety_settings();
        chat_options = chat_options.with_safety_settings(safety_settings);
        
        // System prompt for the planning agent
        let system_prompt = "You are a context enrichment planning agent. Your role is to analyze roleplay conversations and identify what background information would be helpful. Focus on character names, locations, events, and relationships mentioned in the conversation.";
        
        // Create chat request
        let chat_request = ChatRequest::new(messages_vec).with_system(system_prompt);
        
        // Execute the AI call with retry logic
        const MAX_RETRIES: usize = 2;
        let mut last_error = None;
        
        for retry_count in 0..=MAX_RETRIES {
            let enhanced_system = if retry_count > 0 {
                format!("IMPORTANT: This is for a creative writing assistant. {}", system_prompt)
            } else {
                system_prompt.to_string()
            };
            
            let retry_request = ChatRequest::new(chat_request.messages.clone())
                .with_system(&enhanced_system);
            
            match self.state.ai_client
                .exec_chat(&self.model, retry_request, Some(chat_options.clone()))
                .await
            {
                Ok(response) => {
                    // Extract JSON from response
                    let json_result = response.contents
                        .into_iter()
                        .next()
                        .and_then(|content| match content {
                            MessageContent::Text(text) => {
                                // Try to parse as JSON
                                serde_json::from_str::<Value>(&text).ok()
                            },
                            _ => None,
                        })
                        .ok_or_else(|| AppError::GeminiError("Failed to extract JSON from response".to_string()))?;
                    
                    // Parse the structured response
                    let reasoning = json_result.get("reasoning")
                        .and_then(|r| r.as_str())
                        .unwrap_or("No reasoning provided")
                        .to_string();
                    
                    let mut searches = Vec::new();
                    if let Some(searches_array) = json_result.get("searches").and_then(|s| s.as_array()) {
                        for search in searches_array {
                            if let (Some(query), Some(reason), Some(search_type)) = (
                                search.get("query").and_then(|q| q.as_str()),
                                search.get("reason").and_then(|r| r.as_str()),
                                search.get("search_type").and_then(|t| t.as_str()),
                            ) {
                                searches.push(PlannedSearch {
                                    query: query.to_string(),
                                    reason: reason.to_string(),
                                    search_type: search_type.to_string(),
                                });
                            }
                        }
                    }
                    
                    // Ensure we have at least one search
                    if searches.is_empty() {
                        searches.push(PlannedSearch {
                            query: "recent events".to_string(),
                            reason: "No specific searches identified, performing general context search".to_string(),
                            search_type: "all".to_string(),
                        });
                    }
                    
                    let planning_step = AgentStep {
                        step_number: 1,
                        timestamp: Utc::now(),
                        action_type: "planning".to_string(),
                        thought: reasoning.clone(),
                        tool_call: None,
                        result: Some(json!({
                            "planned_searches": searches.clone(),
                            "mode": format!("{:?}", mode)
                        })),
                        tokens_used: 200, // Rough estimate
                        duration_ms: step_start.elapsed().as_millis() as u64,
                    };
                    
                    return Ok((reasoning, searches, planning_step));
                }
                Err(e) => {
                    let error_str = e.to_string();
                    debug!("Planning AI error on attempt {}: {}", retry_count + 1, error_str);
                    
                    if retry_count < MAX_RETRIES {
                        last_error = Some(AppError::GeminiError(format!("Planning failed: {}", e)));
                        continue;
                    }
                    
                    last_error = Some(AppError::GeminiError(format!("Planning failed after retries: {}", e)));
                    break;
                }
            }
        }
        
        // If all AI attempts failed, fall back to a basic search
        warn!("AI planning failed, using fallback search");
        let fallback_searches = vec![
            PlannedSearch {
                query: "recent events".to_string(),
                reason: "General context search (AI planning unavailable)".to_string(),
                search_type: "all".to_string(),
            }
        ];
        
        let planning_step = AgentStep {
            step_number: 1,
            timestamp: Utc::now(),
            action_type: "planning".to_string(),
            thought: "AI planning unavailable, using fallback search".to_string(),
            tool_call: None,
            result: Some(json!({
                "planned_searches": fallback_searches.clone(),
                "mode": format!("{:?}", mode),
                "fallback": true
            })),
            tokens_used: 0,
            duration_ms: step_start.elapsed().as_millis() as u64,
        };
        
        Ok(("Fallback search due to AI unavailability".to_string(), fallback_searches, planning_step))
    }

    /// Build the prompt for the planning phase
    fn build_planning_prompt(&self, messages: &[(String, String)], mode: EnrichmentMode) -> String {
        let mode_context = match mode {
            EnrichmentMode::PreProcessing => {
                "The user just sent a message and is waiting for a response. \
                 Identify any references to past events, characters, or concepts that would \
                 benefit from additional context before generating the AI's response."
            }
            EnrichmentMode::PostProcessing => {
                "The AI has already responded to the user. Now we want to enrich the context \
                 for future reference. Identify key narrative elements, character developments, \
                 or world-building aspects that should be searchable later."
            }
        };

        // Get last few messages for context (limit to avoid huge prompts)
        let recent_messages = messages
            .iter()
            .rev()
            .take(6) // Last 3 exchanges
            .rev()
            .map(|(role, content)| format!("{}: {}", role, content))
            .collect::<Vec<_>>()
            .join("\n\n");

        format!(
            "You are a context enrichment agent analyzing a roleplay conversation.
{}

Recent conversation:
{}

Your task: Plan 2-5 keyword searches to find relevant context from the user's chronicles, lorebooks, and chat history.

For each search, provide:
1. The search query (2-4 keywords)
2. The reason for this search
3. What to search (all/chronicles/lorebooks)

Format your response as:
REASONING: [Your analysis of what context would be helpful]

SEARCH 1:
Query: [keywords]
Reason: [why this search]
Type: [all/chronicles/lorebooks]

SEARCH 2:
Query: [keywords]
Reason: [why this search]
Type: [all/chronicles/lorebooks]

Be specific with character names, locations, and key concepts mentioned.",
            mode_context,
            recent_messages
        )
    }


    /// Step 2: Execute a single search
    async fn execute_search(
        &self, 
        search: &PlannedSearch, 
        user_id: Uuid, 
        chronicle_id: Option<Uuid>
    ) -> Result<(Value, u32), AppError> {
        debug!("Executing search: '{}' for user {}", search.query, user_id);

        let mut params = json!({
            "query": search.query,
            "search_type": search.search_type,
            "limit": 10,
            "user_id": user_id.to_string()  // SECURITY: Pass user_id for filtering
        });

        // Add chronicle_id if provided for prioritization
        if let Some(chron_id) = chronicle_id {
            params["chronicle_id"] = json!(chron_id.to_string());
        }

        let result = self.search_tool
            .execute(&params)
            .await
            .map_err(|e| AppError::BadRequest(format!("Search failed: {}", e)))?;

        // Estimate tokens (rough approximation)
        let tokens = (search.query.len() / 4) as u32 + 10;

        Ok((result, tokens))
    }

    /// Step 3: Synthesize search results into useful context
    async fn synthesize_results(
        &self,
        search_results: &[Value],
        _messages: &[(String, String)],
    ) -> Result<(String, String, AgentStep), AppError> {
        let step_start = Instant::now();

        // Combine all search results
        let mut all_results = Vec::new();
        for result_set in search_results {
            if let Some(results) = result_set.get("results").and_then(|r| r.as_array()) {
                for result in results {
                    if let Some(content) = result.get("content").and_then(|c| c.as_str()) {
                        let result_type = result.get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("unknown");
                        all_results.push(format!("[{}] {}", result_type, content));
                    }
                }
            }
        }

        if all_results.is_empty() {
            info!("No search results to synthesize");
            let empty_step = AgentStep {
                step_number: 0,
                timestamp: Utc::now(),
                action_type: "synthesis".to_string(),
                thought: "No relevant context found".to_string(),
                tool_call: None,
                result: Some(json!({"status": "no_results"})),
                tokens_used: 0,
                duration_ms: step_start.elapsed().as_millis() as u64,
            };
            return Ok((
                String::new(),
                "No relevant context found.".to_string(),
                empty_step
            ));
        }

        // Build synthesis prompt
        let user_message_content = format!(
            "You have found {} pieces of relevant context from searching chronicles and lorebooks. \
             Your task is to synthesize this into a concise summary (2-3 paragraphs) that highlights \
             the most relevant information for the ongoing roleplay conversation.\n\n\
             Focus on:\n\
             - Character relationships and dynamics\n\
             - Recent narrative events\n\
             - World details that directly relate to the current scene\n\
             - Any important backstory or lore\n\n\
             Search Results:\n{}\n\n\
             Provide a coherent summary that the AI can use as context:",
            all_results.len(),
            all_results.join("\n\n")
        );

        // Create structured output schema for synthesis
        let synthesis_schema = json!({
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "A 2-3 paragraph synthesis of the most relevant context"
                },
                "key_points": {
                    "type": "array",
                    "items": {
                        "type": "string"
                    },
                    "maxItems": 5,
                    "description": "Bullet points of the most important facts"
                }
            },
            "required": ["summary"]
        });

        // Create chat messages
        let user_message = GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text(user_message_content),
            options: None,
        };
        
        let prefill_message = GenAiChatMessage {
            role: ChatRole::Assistant,
            content: MessageContent::Text(
                "I'll synthesize the search results into relevant context for the roleplay:".to_string()
            ),
            options: None,
        };
        
        let messages_vec = vec![user_message, prefill_message];
        
        // Build chat options
        let mut chat_options = ChatOptions::default();
        chat_options = chat_options.with_temperature(0.5); // Lower temperature for synthesis
        chat_options = chat_options.with_max_tokens(1024);
        
        // Enable structured output
        let json_schema_spec = JsonSchemaSpec::new(synthesis_schema.clone());
        let response_format = ChatResponseFormat::JsonSchemaSpec(json_schema_spec);
        chat_options = chat_options.with_response_format(response_format);
        
        // Add safety settings
        let safety_settings = create_unrestricted_safety_settings();
        chat_options = chat_options.with_safety_settings(safety_settings);
        
        // System prompt
        let system_prompt = "You are a context synthesis agent for a roleplay assistant. Your role is to take search results from chronicles and lorebooks and create a coherent summary that provides relevant background context.";
        
        // Create chat request
        let chat_request = ChatRequest::new(messages_vec).with_system(system_prompt);
        
        // Try to get AI synthesis
        match self.state.ai_client
            .exec_chat(&self.model, chat_request, Some(chat_options))
            .await
        {
            Ok(response) => {
                // Extract JSON from response
                if let Some(json_result) = response.contents
                    .into_iter()
                    .next()
                    .and_then(|content| match content {
                        MessageContent::Text(text) => serde_json::from_str::<Value>(&text).ok(),
                        _ => None,
                    })
                {
                    let synthesis_text = json_result.get("summary")
                        .and_then(|s| s.as_str())
                        .unwrap_or("Context synthesis unavailable")
                        .to_string();
                    
                    let synthesis_step = AgentStep {
                        step_number: 0, // Will be set by caller
                        timestamp: Utc::now(),
                        action_type: "synthesis".to_string(),
                        thought: "AI synthesis of search results completed".to_string(),
                        tool_call: None,
                        result: Some(json!({
                            "num_results": all_results.len(),
                            "summary_length": synthesis_text.len(),
                            "ai_synthesis": true
                        })),
                        tokens_used: 300, // Rough estimate
                        duration_ms: step_start.elapsed().as_millis() as u64,
                    };
                    
                    let retrieved_context = all_results.join("\n\n---\n\n");
                    return Ok((retrieved_context, synthesis_text, synthesis_step));
                }
            }
            Err(e) => {
                warn!("AI synthesis failed, using raw results: {}", e);
            }
        }
        
        // Fallback: return raw results with simple formatting
        let fallback_summary = format!(
            "Found {} relevant context items from chronicles and lorebooks. \
             The search results include narrative events, character information, and world details \
             that may be relevant to the current conversation.",
            all_results.len()
        );
        
        let synthesis_step = AgentStep {
            step_number: 0,
            timestamp: Utc::now(),
            action_type: "synthesis".to_string(),
            thought: "Fallback synthesis (AI unavailable)".to_string(),
            tool_call: None,
            result: Some(json!({
                "num_results": all_results.len(),
                "fallback": true
            })),
            tokens_used: 0,
            duration_ms: step_start.elapsed().as_millis() as u64,
        };
        
        let retrieved_context = all_results.join("\n\n---\n\n");
        Ok((retrieved_context, fallback_summary, synthesis_step))
    }

    /// Store the analysis in the database for audit trail
    async fn store_analysis(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        agent_reasoning: &str,
        planned_searches: &[PlannedSearch],
        execution_log: &AgentExecutionLog,
        retrieved_context: &str,
        analysis_summary: &str,
        total_tokens: u32,
        execution_time_ms: u64,
        mode: EnrichmentMode,
        session_dek: &[u8],
    ) -> Result<(), AppError> {
        use diesel::prelude::*;
        use crate::models::NewAgentContextAnalysis;
        use crate::schema::agent_context_analysis;
        
        // Convert session_dek to SecretBox
        let dek_secret = SecretBox::new(Box::new(session_dek.to_vec()));
        
        // Convert planned searches to JSON value
        let planned_searches_json = serde_json::to_value(planned_searches)?;
        
        // Create new agent context analysis record with encryption
        let new_analysis = NewAgentContextAnalysis::new_encrypted(
            session_id,
            user_id,
            match mode {
                EnrichmentMode::PreProcessing => crate::models::AnalysisType::PreProcessing,
                EnrichmentMode::PostProcessing => crate::models::AnalysisType::PostProcessing,
            },
            agent_reasoning,
            &planned_searches_json,
            &serde_json::to_value(execution_log)?,
            retrieved_context,
            analysis_summary,
            total_tokens,
            execution_time_ms,
            &self.model,
            &dek_secret,
        )?;
        
        // Get database connection
        let conn = self.state.pool.get()
            .await
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to get DB connection: {}", e)))?;
        
        // Insert or update the analysis record (upsert on session_id + analysis_type)
        conn.interact(move |conn| {
            diesel::insert_into(agent_context_analysis::table)
                .values(&new_analysis)
                .on_conflict((
                    agent_context_analysis::chat_session_id,
                    agent_context_analysis::analysis_type,
                ))
                .do_update()
                .set((
                    agent_context_analysis::agent_reasoning.eq(&new_analysis.agent_reasoning),
                    agent_context_analysis::agent_reasoning_nonce.eq(&new_analysis.agent_reasoning_nonce),
                    agent_context_analysis::planned_searches.eq(&new_analysis.planned_searches),
                    agent_context_analysis::execution_log.eq(&new_analysis.execution_log),
                    agent_context_analysis::execution_log_nonce.eq(&new_analysis.execution_log_nonce),
                    agent_context_analysis::retrieved_context.eq(&new_analysis.retrieved_context),
                    agent_context_analysis::retrieved_context_nonce.eq(&new_analysis.retrieved_context_nonce),
                    agent_context_analysis::analysis_summary.eq(&new_analysis.analysis_summary),
                    agent_context_analysis::analysis_summary_nonce.eq(&new_analysis.analysis_summary_nonce),
                    agent_context_analysis::total_tokens_used.eq(&new_analysis.total_tokens_used),
                    agent_context_analysis::execution_time_ms.eq(&new_analysis.execution_time_ms),
                    agent_context_analysis::model_used.eq(&new_analysis.model_used),
                    agent_context_analysis::updated_at.eq(diesel::dsl::now),
                ))
                .execute(conn)
        })
        .await
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to interact with DB: {}", e)))?
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to store agent analysis: {}", e)))?;
        
        info!(
            "Stored agent analysis: session={}, mode={:?}, tokens={}, time={}ms",
            session_id, mode, total_tokens, execution_time_ms
        );
        
        Ok(())
    }
}