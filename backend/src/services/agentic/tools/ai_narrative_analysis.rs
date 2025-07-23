//! AI-Powered Narrative Analysis Tools
//!
//! This module provides intelligent narrative analysis components that replace
//! hardcoded logic with AI-driven intelligence using Flash/Flash-Lite.
//!
//! Key components:
//! - AiTriageAnalyzer: Intelligent significance assessment
//! - AiPromptGenerator: Context-aware prompt generation
//! - AiPlanGenerator: Intelligent action planning

use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::{
    auth::session_dek::SessionDek,
    errors::AppError,
    models::chats::ChatMessage,
    state::AppState,
};

use super::super::agent_runner::{TriageResult, ActionPlan, PlannedAction, UserPersonaContext};

/// AI-powered triage analyzer that intelligently assesses narrative significance
pub struct AiTriageAnalyzer {
    app_state: Arc<AppState>,
}

impl AiTriageAnalyzer {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Perform intelligent triage analysis using AI to determine significance
    pub async fn analyze_significance(
        &self,
        messages: &[ChatMessage],
        session_dek: &SessionDek,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        persona_context: Option<&UserPersonaContext>,
        is_re_chronicle: bool,
        context: &str,
    ) -> Result<TriageResult, AppError> {
        debug!("Starting AI-driven triage analysis for {} messages", messages.len());

        // Use AI to generate a context-aware triage prompt
        let triage_prompt = self.generate_intelligent_triage_prompt(
            messages,
            session_dek,
            user_id,
            chronicle_id,
            persona_context,
            is_re_chronicle,
            context,
        ).await?;

        // Use Flash-Lite for fast, cost-effective triage
        let chat_request = genai::chat::ChatRequest::from_user(triage_prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1000)
            .with_temperature(0.2); // Low temperature for consistent analysis

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.fast_model, chat_request, Some(chat_options))
            .await
            .map_err(|e| AppError::LlmClientError(format!("AI triage analysis failed: {}", e)))?;

        let ai_response = response.first_content_text_as_str().unwrap_or_default();
        self.parse_triage_response(ai_response)
    }

    /// Generate an intelligent, context-aware triage prompt
    async fn generate_intelligent_triage_prompt(
        &self,
        messages: &[ChatMessage],
        session_dek: &SessionDek,
        user_id: Uuid,
        chronicle_id: Option<Uuid>,
        persona_context: Option<&UserPersonaContext>,
        is_re_chronicle: bool,
        existing_context: &str,
    ) -> Result<String, AppError> {
        debug!("Generating AI-driven triage prompt");

        // Build conversation text
        let conversation_text = self.build_conversation_text(messages, session_dek).await?;

        // Build persona context
        let persona_section = if let Some(persona) = persona_context {
            format!("\n{}\n", persona.to_prompt_context())
        } else {
            String::new()
        };

        // Get username from database
        let username = match self.app_state.pool.get().await {
            Ok(conn) => {
                match conn.interact(move |conn| crate::auth::get_user(conn, user_id)).await {
                    Ok(Ok(user)) => user.username,
                    Ok(Err(e)) => {
                        warn!("Failed to fetch user details: {}", e);
                        format!("User {}", user_id)
                    }
                    Err(e) => {
                        warn!("Database interaction error: {}", e);
                        format!("User {}", user_id)
                    }
                }
            }
            Err(e) => {
                warn!("Failed to get database connection: {}", e);
                format!("User {}", user_id)
            }
        };
        
        // Get persona name for context
        let persona_name = persona_context
            .map(|p| p.persona_name.clone())
            .unwrap_or_else(|| username.clone());
        
        // Use AI to generate an intelligent prompt based on context
        let prompt_generation_request = format!(
            r#"Generate an intelligent narrative triage prompt for analyzing a roleplay conversation.

CONTEXT:
- User: {} (account username)
- Persona: {} (character being played)
- Chronicle ID: {}
- Re-chronicle mode: {}
- Has persona context: {}
- Has existing chronicles: {}
- Conversation length: {} messages
{}
CONVERSATION PREVIEW:
{}

Generate a concise but comprehensive triage prompt that:
1. Asks the AI to analyze narrative significance
2. Considers the specific context (re-chronicle vs normal)
3. Includes persona awareness if available
4. Accounts for existing chronicles to avoid duplication
5. Considers character-specific patterns and preferences
6. Requests structured JSON response with significance, summary, event_type, and confidence

Return ONLY the triage prompt text, optimized for the given context."#,
            username,
            persona_name,
            chronicle_id.map(|id| id.to_string()).unwrap_or_else(|| "None".to_string()),
            is_re_chronicle,
            persona_context.is_some(),
            !existing_context.is_empty(),
            messages.len(),
            persona_section,
            if conversation_text.len() > 500 {
                format!("{}...", &conversation_text[..500])
            } else {
                conversation_text.clone()
            }
        );

        // Use Flash for prompt generation
        let chat_request = genai::chat::ChatRequest::from_user(prompt_generation_request);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(2000)
            .with_temperature(0.3);

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.fast_model, chat_request, Some(chat_options))
            .await
            .map_err(|e| AppError::LlmClientError(format!("Prompt generation failed: {}", e)))?;

        let ai_generated_prompt = response.first_content_text_as_str().unwrap_or_default().to_string();

        // Combine with actual conversation and context
        let final_prompt = format!(
            r#"{}

{}

CONVERSATION TO ANALYZE:
{}

EXISTING CHRONICLES:
{}

Respond with JSON:
{{
    "is_significant": boolean,
    "summary": "string",
    "event_category": "string", 
    "event_type": "string",
    "narrative_action": "string",
    "primary_agent": "string",
    "primary_patient": "string", 
    "confidence": float
}}"#,
            ai_generated_prompt,
            persona_section,
            conversation_text,
            existing_context
        );

        Ok(final_prompt)
    }

    /// Build conversation text from messages
    async fn build_conversation_text(
        &self,
        messages: &[ChatMessage],
        session_dek: &SessionDek,
    ) -> Result<String, AppError> {
        let mut conversation = String::new();

        for message in messages {
            // Decrypt message content
            let nonce = message.content_nonce.as_deref().unwrap_or(&[0u8; 12]); // Fallback nonce for tests
            let decrypted_content = self.app_state.encryption_service
                .decrypt(&message.content, nonce, session_dek.expose_bytes())
                .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to decrypt message: {}", e)))?;
            
            let content_str = String::from_utf8_lossy(&decrypted_content);

            conversation.push_str(&format!("{}: {}\n", 
                match message.message_type {
                    crate::models::chats::MessageRole::User => "User",
                    crate::models::chats::MessageRole::Assistant => "Assistant",
                    crate::models::chats::MessageRole::System => "System",
                },
                content_str
            ));
        }

        Ok(conversation)
    }

    /// Parse AI triage response intelligently
    fn parse_triage_response(&self, ai_response: &str) -> Result<TriageResult, AppError> {
        // Extract JSON from potential markdown or text
        let json_content = self.extract_json_from_response(ai_response)?;
        
        let parsed: Value = serde_json::from_str(&json_content)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to parse triage JSON: {}", e)))?;

        let is_significant = parsed.get("is_significant")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let summary = parsed.get("summary")
            .and_then(|v| v.as_str())
            .unwrap_or("No summary provided")
            .to_string();

        let event_type = parsed.get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN")
            .to_string();

        let confidence = parsed.get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.5) as f32;

        Ok(TriageResult {
            is_significant,
            summary,
            event_type,
            confidence,
            reasoning: "AI-driven triage analysis using Flash-Lite".to_string(),
        })
    }

    /// Extract JSON from AI response (handles markdown, etc.)
    fn extract_json_from_response(&self, response: &str) -> Result<String, AppError> {
        let cleaned = if response.trim().starts_with("```json") {
            let start = response.find("```json").unwrap() + 7;
            if let Some(end) = response[start..].find("```") {
                response[start..start + end].trim()
            } else {
                response[start..].trim()
            }
        } else if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                &response[start..=end]
            } else {
                response
            }
        } else {
            response
        };

        Ok(cleaned.to_string())
    }
}

/// AI-powered action plan generator
pub struct AiPlanGenerator {
    app_state: Arc<AppState>,
}

impl AiPlanGenerator {
    pub fn new(app_state: Arc<AppState>) -> Self {
        Self { app_state }
    }

    /// Generate intelligent action plan based on triage and context
    pub async fn generate_intelligent_plan(
        &self,
        triage_result: &TriageResult,
        knowledge_context: &Value,
        chronicle_id: Option<Uuid>,
        chronicle_was_just_created: bool,
        persona_context: Option<&UserPersonaContext>,
        is_re_chronicle: bool,
        available_tools: &[String],
    ) -> Result<ActionPlan, AppError> {
        debug!("Generating AI-driven action plan for: {}", triage_result.summary);

        // Use AI to understand what tools are needed based on the narrative context
        let plan_prompt = self.build_intelligent_planning_prompt(
            triage_result,
            knowledge_context,
            chronicle_id,
            chronicle_was_just_created,
            persona_context,
            is_re_chronicle,
            available_tools,
        ).await?;

        // Use Flash for planning (more capable than Flash-Lite)
        let chat_request = genai::chat::ChatRequest::from_user(plan_prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(3000)
            .with_temperature(0.4); // Slightly higher creativity for planning

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.fast_model, chat_request, Some(chat_options))
            .await
            .map_err(|e| AppError::LlmClientError(format!("AI plan generation failed: {}", e)))?;

        let ai_response = response.first_content_text_as_str().unwrap_or_default();
        self.parse_action_plan_response(ai_response)
    }

    /// Build intelligent planning prompt based on context
    async fn build_intelligent_planning_prompt(
        &self,
        triage_result: &TriageResult,
        knowledge_context: &Value,
        chronicle_id: Option<Uuid>,
        chronicle_was_just_created: bool,
        persona_context: Option<&UserPersonaContext>,
        is_re_chronicle: bool,
        available_tools: &[String],
    ) -> Result<String, AppError> {
        // Use AI to generate a context-specific planning prompt
        let context_analysis_request = format!(
            r#"Analyze this narrative situation and determine what actions should be taken:

TRIAGE RESULT:
- Significant: {}
- Summary: {}
- Event Type: {}
- Confidence: {}

CONTEXT:
- Re-chronicle mode: {}
- Chronicle just created: {}
- Has persona context: {}
- Available tools: {:?}

KNOWLEDGE CONTEXT:
{}

Based on this analysis, what type of narrative actions should be prioritized? Consider:
1. Whether to create chronicle events vs lorebook entries
2. Whether deduplication is important (not in re-chronicle mode)
3. What entities or concepts need to be tracked
4. The confidence level and how it affects action selection

Provide a brief strategic analysis of what should be done."#,
            triage_result.is_significant,
            triage_result.summary,
            triage_result.event_type,
            triage_result.confidence,
            is_re_chronicle,
            chronicle_was_just_created,
            persona_context.is_some(),
            available_tools,
            knowledge_context
        );

        // Get AI strategic analysis
        let chat_request = genai::chat::ChatRequest::from_user(context_analysis_request);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1000)
            .with_temperature(0.3);

        let response = self.app_state.ai_client
            .exec_chat(&self.app_state.config.fast_model, chat_request, Some(chat_options))
            .await
            .map_err(|e| AppError::LlmClientError(format!("Strategic analysis failed: {}", e)))?;

        let strategic_analysis = response.first_content_text_as_str().unwrap_or_default();

        // Build persona section
        let persona_section = if let Some(persona) = persona_context {
            format!("\n{}\n", persona.to_prompt_context())
        } else {
            String::new()
        };

        // Build tools description
        let tools_description = self.build_tools_description(available_tools);

        // Create comprehensive planning prompt
        let planning_prompt = format!(
            r#"You are an intelligent narrative planning agent. Based on the strategic analysis below, create a specific action plan.

STRATEGIC ANALYSIS:
{}

EVENT TO PROCESS:
- Type: {}
- Summary: {}
- Confidence: {}

{}

AVAILABLE TOOLS:
{}

CHRONICLE ID: {}
CHRONICLE JUST CREATED: {}

Create a JSON action plan with specific tool calls and parameters:
{{
    "reasoning": "string explaining your strategic reasoning",
    "confidence": 0.0-1.0 confidence score for this plan's success,
    "actions": [
        {{
            "tool_name": "string",
            "parameters": {{}},
            "reasoning": "string explaining this specific action"
        }}
    ]
}}

Guidelines:
- Be specific about tool parameters
- Consider the confidence level when deciding action scope
- In re-chronicle mode, be more generous with event creation
- Ensure proper actor extraction for chronicle events
- Balance between events (temporal) and lorebook entries (persistent)"#,
            strategic_analysis,
            triage_result.event_type,
            triage_result.summary,
            triage_result.confidence,
            persona_section,
            tools_description,
            chronicle_id.map(|id| id.to_string()).unwrap_or_else(|| "None".to_string()),
            chronicle_was_just_created
        );

        Ok(planning_prompt)
    }

    /// Build tools description based on available tools
    fn build_tools_description(&self, available_tools: &[String]) -> String {
        let mut description = String::new();
        
        for tool_name in available_tools {
            match tool_name.as_str() {
                "create_chronicle_event" => {
                    description.push_str("- create_chronicle_event: Record temporal, player-centric events that happened at specific times\n");
                }
                "create_lorebook_entry" => {
                    description.push_str("- create_lorebook_entry: Create NEW lorebook entries for persistent world concepts\n");
                }
                "update_lorebook_entry" => {
                    description.push_str("- update_lorebook_entry: Update existing lorebook entries when world state changes\n");
                }
                "search_knowledge_base" => {
                    description.push_str("- search_knowledge_base: Find existing information\n");
                }
                _ => {
                    description.push_str(&format!("- {}: Available tool\n", tool_name));
                }
            }
        }
        
        description
    }

    /// Parse action plan response from AI
    fn parse_action_plan_response(&self, ai_response: &str) -> Result<ActionPlan, AppError> {
        let json_content = self.extract_json_from_response(ai_response)?;
        
        let parsed: Value = serde_json::from_str(&json_content)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to parse action plan JSON: {}", e)))?;

        let reasoning = parsed.get("reasoning")
            .and_then(|v| v.as_str())
            .unwrap_or("No reasoning provided")
            .to_string();

        let actions = parsed.get("actions")
            .and_then(|v| v.as_array())
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|action| {
                let tool_name = action.get("tool_name")?.as_str()?.to_string();
                let parameters = action.get("parameters")?.clone();
                let action_reasoning = action.get("reasoning")
                    .and_then(|v| v.as_str())
                    .unwrap_or("No reasoning provided")
                    .to_string();

                Some(PlannedAction {
                    tool_name,
                    parameters,
                    reasoning: action_reasoning,
                })
            })
            .collect();

        // Extract confidence from AI response (AI should provide this)
        let confidence = parsed.get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or_else(|| {
                warn!("AI did not provide confidence score in action plan - this is a prompt engineering issue");
                0.5 // Fallback only when AI fails to provide confidence
            }) as f32;

        Ok(ActionPlan {
            reasoning,
            actions,
            confidence,
        })
    }

    /// Extract JSON from response
    fn extract_json_from_response(&self, response: &str) -> Result<String, AppError> {
        let cleaned = if response.trim().starts_with("```json") {
            let start = response.find("```json").unwrap() + 7;
            if let Some(end) = response[start..].find("```") {
                response[start..start + end].trim()
            } else {
                response[start..].trim()
            }
        } else if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                &response[start..=end]
            } else {
                response
            }
        } else {
            response
        };

        Ok(cleaned.to_string())
    }
}