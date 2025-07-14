use std::sync::Arc;
use uuid::Uuid;
use tracing::{info, debug, warn, instrument};

use crate::{
    errors::AppError,
    services::{
        EcsEntityManager,
        planning::types::*,
    },
    models::{
        chats::ChatMessage,
        ecs::*,
    },
    llm::AiClient,
    config::Config,
};
use genai::chat::{ChatRequest, ChatOptions, MessageContent};

/// Service for analyzing ECS inconsistencies using Flash-powered narrative analysis
pub struct EcsConsistencyAnalyzer {
    ecs_manager: Arc<EcsEntityManager>,
    flash_client: Arc<dyn AiClient + Send + Sync>,
    config: Config,
}

impl EcsConsistencyAnalyzer {
    pub fn new(
        ecs_manager: Arc<EcsEntityManager>,
        flash_client: Arc<dyn AiClient + Send + Sync>,
        config: Config,
    ) -> Self {
        Self {
            ecs_manager,
            flash_client,
            config,
        }
    }

    /// Analyze validation failures to determine if they might be due to ECS inconsistency
    #[instrument(skip(self, plan, failures, recent_context))]
    pub async fn analyze_inconsistency(
        &self,
        plan: &Plan,
        failures: &[ValidationFailure],
        user_id: Uuid,
        recent_context: &[ChatMessage],
    ) -> Result<Option<InconsistencyAnalysis>, AppError> {
        info!("Analyzing potential ECS inconsistency for plan: {}", plan.goal);
        debug!("Found {} validation failures to analyze", failures.len());

        // Skip analysis if no recent context available
        if recent_context.is_empty() {
            debug!("No recent context available for inconsistency analysis");
            return Ok(None);
        }

        // Get relevant ECS state for context
        let ecs_state_summary = self.get_relevant_ecs_state(plan, user_id).await?;

        // Build analysis prompt for Flash
        let analysis_prompt = self.build_inconsistency_analysis_prompt(
            plan,
            failures,
            recent_context,
            &ecs_state_summary,
        );

        // Use Flash for inconsistency analysis
        let analysis_result = self.analyze_with_flash(&analysis_prompt).await?;

        // Parse the Flash response into structured analysis
        self.parse_inconsistency_analysis(analysis_result, plan, failures).await
    }

    /// Build the prompt for Flash inconsistency analysis
    fn build_inconsistency_analysis_prompt(
        &self,
        plan: &Plan,
        failures: &[ValidationFailure],
        recent_context: &[ChatMessage],
        ecs_state_summary: &str,
    ) -> String {
        let context_text = self.format_chat_context(recent_context);
        let failures_text = self.format_validation_failures(failures);

        format!(r#"
You are an intelligent ECS State Reconciliation Analyzer. Your task is to determine if plan validation failures are due to ECS state inconsistencies rather than genuinely invalid plans.

RECENT CONVERSATION CONTEXT:
{}

PLAN GOAL: {}

VALIDATION FAILURES:
{}

CURRENT ECS STATE:
{}

ANALYSIS TASK:
Based on the conversation context, determine if any validation failures suggest the ECS state is outdated/incomplete rather than the plan being invalid.

For each failure, consider:
1. Does the conversation imply this state should exist?
2. Is there narrative evidence suggesting the ECS is behind the story?
3. Would creating this state make logical sense given the context?
4. Is this a common type of ECS lag (movement, relationships, components)?

RESPONSE FORMAT (JSON):
{{
  "has_inconsistency": boolean,
  "inconsistency_type": "MissingMovement" | "MissingComponent" | "MissingRelationship" | "OutdatedState" | "TemporalMismatch" | null,
  "confidence_score": 0.0-1.0,
  "narrative_evidence": ["specific quotes or implications from conversation"],
  "ecs_state_summary": "brief description of current state that seems wrong",
  "repair_reasoning": "explanation of why this repair makes sense",
  "specific_failures": ["list of failure IDs that could be repaired"]
}}

Guidelines:
- Only suggest repairs for high-confidence inconsistencies (>0.7)
- Consider multiple conversation turns for context
- Look for implicit narrative state changes
- Be conservative - err on side of caution
- Focus on common inconsistency patterns

Analyze the failures and provide your assessment:
"#, context_text, plan.goal, failures_text, ecs_state_summary)
    }

    /// Format chat context for analysis
    fn format_chat_context(&self, messages: &[ChatMessage]) -> String {
        messages.iter()
            .enumerate()
            .map(|(i, msg)| {
                // Convert content from Vec<u8> to String (assuming UTF-8)
                let content_str = String::from_utf8_lossy(&msg.content);
                format!("{}. {} ({}): {}", 
                    i + 1, 
                    msg.message_type.to_string(), 
                    msg.created_at.format("%H:%M:%S"),
                    // Sanitize message content to prevent injection
                    self.sanitize_text(&content_str)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Format validation failures for analysis
    fn format_validation_failures(&self, failures: &[ValidationFailure]) -> String {
        failures.iter()
            .map(|f| {
                format!("- {} ({}): {}", 
                    f.action_id, 
                    format!("{:?}", f.failure_type),
                    // Sanitize failure messages
                    self.sanitize_text(&f.message)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Get relevant ECS state summary for context
    async fn get_relevant_ecs_state(&self, plan: &Plan, user_id: Uuid) -> Result<String, AppError> {
        let mut state_summary = Vec::new();

        // Extract entity IDs from plan actions and preconditions
        let mut entity_ids = std::collections::HashSet::new();
        
        for action in &plan.actions {
            // Extract from parameters (entity IDs are usually UUID strings)
            if let serde_json::Value::Object(params) = &action.parameters {
                for value in params.values() {
                    if let Some(id_str) = value.as_str() {
                        if let Ok(entity_id) = Uuid::parse_str(id_str) {
                            entity_ids.insert(entity_id);
                        }
                    }
                }
            }

            // Extract from preconditions
            if let Some(checks) = &action.preconditions.entity_exists {
                for check in checks {
                    if let Some(id_str) = &check.entity_id {
                        if let Ok(entity_id) = Uuid::parse_str(id_str) {
                            entity_ids.insert(entity_id);
                        }
                    }
                }
            }

            if let Some(checks) = &action.preconditions.entity_at_location {
                for check in checks {
                    if let Ok(entity_id) = Uuid::parse_str(&check.entity_id) {
                        entity_ids.insert(entity_id);
                    }
                    if let Ok(location_id) = Uuid::parse_str(&check.location_id) {
                        entity_ids.insert(location_id);
                    }
                }
            }

            if let Some(checks) = &action.preconditions.entity_has_component {
                for check in checks {
                    if let Ok(entity_id) = Uuid::parse_str(&check.entity_id) {
                        entity_ids.insert(entity_id);
                    }
                }
            }

            if let Some(check) = &action.preconditions.inventory_has_space {
                if let Ok(entity_id) = Uuid::parse_str(&check.entity_id) {
                    entity_ids.insert(entity_id);
                }
            }

            if let Some(checks) = &action.preconditions.relationship_exists {
                for check in checks {
                    if let Ok(source_id) = Uuid::parse_str(&check.source_entity) {
                        entity_ids.insert(source_id);
                    }
                    if let Ok(target_id) = Uuid::parse_str(&check.target_entity) {
                        entity_ids.insert(target_id);
                    }
                }
            }
        }

        // Get entity states for context (limit to prevent token overflow)
        let limited_entities: Vec<_> = entity_ids.into_iter().take(10).collect();
        
        for entity_id in limited_entities {
            match self.ecs_manager.get_entity(user_id, entity_id).await {
                Ok(Some(entity_result)) => {
                    let mut entity_summary = format!("Entity {}: ", entity_id);
                    
                    // Add entity name if available
                    if let Some(name_component) = entity_result.components.iter()
                        .find(|c| c.component_type == "Name") {
                        if let Ok(name_data) = serde_json::from_value::<serde_json::Value>(name_component.component_data.clone()) {
                            if let Some(name) = name_data.get("name").and_then(|n| n.as_str()) {
                                entity_summary.push_str(&format!("'{}' ", self.sanitize_text(name)));
                            }
                        }
                    }

                    // Add component types
                    let component_types: Vec<String> = entity_result.components.iter()
                        .map(|c| c.component_type.clone())
                        .collect();
                    entity_summary.push_str(&format!("(components: {})", component_types.join(", ")));

                    // Add location if available
                    if let Some(parent_link) = entity_result.components.iter()
                        .find(|c| c.component_type == "ParentLink") {
                        if let Ok(parent_data) = serde_json::from_value::<ParentLinkComponent>(parent_link.component_data.clone()) {
                            entity_summary.push_str(&format!(" at {}", parent_data.parent_entity_id));
                        }
                    }

                    state_summary.push(entity_summary);
                }
                Ok(None) => {
                    state_summary.push(format!("Entity {}: NOT FOUND", entity_id));
                }
                Err(_) => {
                    state_summary.push(format!("Entity {}: ACCESS ERROR", entity_id));
                }
            }
        }

        if state_summary.is_empty() {
            Ok("No relevant ECS state found for analysis".to_string())
        } else {
            Ok(state_summary.join("\n"))
        }
    }

    /// Use Flash for inconsistency analysis
    async fn analyze_with_flash(&self, prompt: &str) -> Result<String, AppError> {
        debug!("Sending inconsistency analysis prompt to Flash");

        let chat_request = ChatRequest::from_user(prompt);

        let chat_options = ChatOptions {
            temperature: Some(0.3), // Low temperature for consistent analysis
            max_tokens: Some(1000),
            ..Default::default()
        };

        let response = self.flash_client.exec_chat(
            &self.config.agentic_extraction_model,
            chat_request,
            Some(chat_options),
        ).await
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Flash analysis failed: {}", e)))?;

        let response_text = response.contents
            .iter()
            .find_map(|content| {
                if let MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "No text content in response".to_string());

        Ok(response_text)
    }

    /// Parse Flash response into structured inconsistency analysis
    async fn parse_inconsistency_analysis(
        &self,
        analysis_text: String,
        plan: &Plan,
        failures: &[ValidationFailure],
    ) -> Result<Option<InconsistencyAnalysis>, AppError> {
        debug!("Parsing Flash inconsistency analysis response");

        // Try to parse as JSON
        match serde_json::from_str::<serde_json::Value>(&analysis_text) {
            Ok(json) => {
                let has_inconsistency = json.get("has_inconsistency")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if !has_inconsistency {
                    debug!("Flash analysis found no ECS inconsistency");
                    return Ok(None);
                }

                let inconsistency_type = json.get("inconsistency_type")
                    .and_then(|v| v.as_str())
                    .and_then(|s| self.parse_inconsistency_type(s))
                    .unwrap_or(InconsistencyType::OutdatedState);

                let confidence_score = json.get("confidence_score")
                    .and_then(|v| v.as_f64())
                    .map(|f| f as f32)
                    .unwrap_or(0.0)
                    .clamp(0.0, 1.0); // Ensure valid range

                let narrative_evidence = json.get("narrative_evidence")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| self.sanitize_text(s))
                            .collect()
                    })
                    .unwrap_or_default();

                let ecs_state_summary = json.get("ecs_state_summary")
                    .and_then(|v| v.as_str())
                    .map(|s| self.sanitize_text(s))
                    .unwrap_or_else(|| "ECS state appears inconsistent".to_string());

                let repair_reasoning = json.get("repair_reasoning")
                    .and_then(|v| v.as_str())
                    .map(|s| self.sanitize_text(s))
                    .unwrap_or_else(|| "Repair needed to align ECS with narrative".to_string());

                info!("Flash identified {} inconsistency with confidence {}", 
                      format!("{:?}", inconsistency_type), confidence_score);

                Ok(Some(InconsistencyAnalysis {
                    inconsistency_type,
                    narrative_evidence,
                    ecs_state_summary,
                    repair_reasoning,
                    detection_timestamp: chrono::Utc::now(),
                }))
            }
            Err(e) => {
                warn!("Failed to parse Flash analysis as JSON: {}", e);
                debug!("Flash response was: {}", analysis_text);
                
                // Fallback: if response contains key indicators, create basic analysis
                if analysis_text.to_lowercase().contains("inconsistency") &&
                   analysis_text.to_lowercase().contains("repair") {
                    Ok(Some(InconsistencyAnalysis {
                        inconsistency_type: InconsistencyType::OutdatedState,
                        narrative_evidence: vec![
                            "Flash analysis suggested inconsistency but response format was invalid".to_string()
                        ],
                        ecs_state_summary: "Unable to parse detailed state analysis".to_string(),
                        repair_reasoning: "Fallback analysis indicated potential repair needed".to_string(),
                        detection_timestamp: chrono::Utc::now(),
                    }))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Parse inconsistency type from string
    fn parse_inconsistency_type(&self, type_str: &str) -> Option<InconsistencyType> {
        match type_str {
            "MissingMovement" => Some(InconsistencyType::MissingMovement),
            "MissingComponent" => Some(InconsistencyType::MissingComponent),
            "MissingRelationship" => Some(InconsistencyType::MissingRelationship),
            "OutdatedState" => Some(InconsistencyType::OutdatedState),
            "TemporalMismatch" => Some(InconsistencyType::TemporalMismatch),
            _ => None,
        }
    }

    /// Sanitize text to prevent injection attacks and limit length
    fn sanitize_text(&self, text: &str) -> String {
        text.chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace() || ".,!?-_()[]{}:;'\"".contains(*c))
            .take(1000) // Limit length to prevent token overflow
            .collect()
    }
}