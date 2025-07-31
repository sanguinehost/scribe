// backend/src/services/orchestrator/reasoning.rs
//
// Reasoning Loop Implementation
// Implements the 5-phase reasoning loop with Progressive Response optimization

use genai::chat::{ChatOptions, ChatRequest, ChatResponseFormat, JsonSchemaSpec, SafetySetting, HarmCategory, HarmBlockThreshold};
use serde_json::{json, Value as JsonValue};
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, info, warn};

use crate::{
    llm::AiClient,
    services::{
        agentic::unified_tool_registry::UnifiedToolRegistry,
        task_queue::EnrichmentTaskPayload,
    },
};

use super::{
    errors::OrchestratorError,
    types::*,
    structured_output::*,
};

/// Reasoning engine that implements the 5-phase loop with hierarchical agent integration pattern
/// 
/// This implementation demonstrates the structured output pattern and shows how the
/// Strategic, Tactical, and Perception agents would be integrated. Full integration
/// requires dependency resolution for EcsEntityManager, PlanningService, etc.
pub struct ReasoningEngine {
    ai_client: Arc<dyn AiClient>,
    model_name: String,
    // TODO: Hierarchical agent integration requires these dependencies:
    // - ecs_entity_manager: Arc<EcsEntityManager>
    // - planning_service: Arc<PlanningService>
    // - plan_validator: Arc<PlanValidatorService>
    // - redis_client: Arc<redis::Client>
    // - app_state: Arc<AppState>
}

impl ReasoningEngine {
    pub fn new(ai_client: Arc<dyn AiClient>, model_name: String) -> Self {
        // TODO: Full hierarchical agent integration would create agents here:
        // let strategic_agent = StrategicAgent::new(ai_client.clone(), ecs_entity_manager.clone(), redis_client.clone(), config.strategic_agent_model.clone());
        // let tactical_agent = TacticalAgent::new(ai_client.clone(), ecs_entity_manager.clone(), planning_service.clone(), plan_validator.clone(), redis_client.clone());
        // let perception_agent = PerceptionAgent::new(ai_client.clone(), ecs_entity_manager.clone(), planning_service.clone(), plan_validator.clone(), redis_client.clone(), app_state.clone(), config.perception_agent_model.clone());
        
        Self {
            ai_client,
            model_name,
        }
    }

    /// Helper method to analyze a prompt with structured output and return JSON response
    async fn analyze_with_structured_output(
        &self, 
        prompt: &str, 
        schema: JsonValue
    ) -> Result<JsonValue, OrchestratorError> {
        let request = ChatRequest::new(vec![
            genai::chat::ChatMessage::user(prompt)
        ]);

        // Create safety settings to allow fictional content
        let safety_settings = vec![
            SafetySetting::new(HarmCategory::Harassment, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::HateSpeech, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::SexuallyExplicit, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::DangerousContent, HarmBlockThreshold::BlockNone),
            SafetySetting::new(HarmCategory::CivicIntegrity, HarmBlockThreshold::BlockNone),
        ];

        let json_schema_spec = JsonSchemaSpec::new(schema);
        let response_format = ChatResponseFormat::JsonSchemaSpec(json_schema_spec);

        // Dynamically set max_tokens based on the expected response size
        let max_tokens = if prompt.contains("MAXIMUM 5 steps") {
            Some(8000) // Smaller limit for concise Plan phase
        } else {
            Some(16000) // Default for other phases
        };
        
        let options = ChatOptions {
            temperature: Some(0.7),
            max_tokens,
            response_format: Some(response_format),
            safety_settings: Some(safety_settings),
            ..Default::default()
        };

        let response = self.ai_client
            .exec_chat(&self.model_name, request, Some(options))
            .await
            .map_err(|e| OrchestratorError::ReasoningError(format!("AI client error: {}", e)))?;

        // Extract the text response
        let text = response.first_content_text_as_str()
            .ok_or_else(|| OrchestratorError::ReasoningError("No text content in AI response".to_string()))?
            .to_string();

        // Parse JSON directly (structured output should return valid JSON)
        match serde_json::from_str(&text) {
            Ok(json) => Ok(json),
            Err(e) => {
                warn!("Structured output JSON parsing failed. Error: {}, Response: {}", e, text);
                
                // Try to recover from truncated JSON by closing open structures
                if e.to_string().contains("EOF") {
                    if let Ok(recovered) = self.attempt_json_recovery(&text) {
                        info!("Successfully recovered truncated JSON response");
                        return Ok(recovered);
                    }
                }
                
                Err(OrchestratorError::ReasoningError(
                    format!("Failed to parse structured output JSON: {}. Response: {}", e, text)
                ))
            }
        }
    }

    /// Attempt to recover from truncated JSON by intelligently closing open structures
    fn attempt_json_recovery(&self, truncated_json: &str) -> Result<JsonValue, serde_json::Error> {
        let mut recovered = truncated_json.to_string();
        
        // Track structure stack to close in proper order
        let mut structure_stack = Vec::new();
        let mut in_string = false;
        let mut escape = false;
        let mut last_char = ' ';
        
        for ch in truncated_json.chars() {
            if escape {
                escape = false;
                last_char = ch;
                continue;
            }
            
            match ch {
                '\\' => escape = true,
                '"' if !escape => in_string = !in_string,
                '{' if !in_string => structure_stack.push('{'),
                '}' if !in_string => {
                    if let Some(&'{') = structure_stack.last() {
                        structure_stack.pop();
                    }
                },
                '[' if !in_string => structure_stack.push('['),
                ']' if !in_string => {
                    if let Some(&'[') = structure_stack.last() {
                        structure_stack.pop();
                    }
                },
                _ => {}
            }
            last_char = ch;
        }
        
        // If we're in the middle of a string, close it
        if in_string {
            // Check if we need to add a comma before closing
            if last_char != '"' && last_char != ',' && !last_char.is_whitespace() {
                recovered.push('"');
            } else {
                recovered.push('"');
            }
        }
        
        // If the last character was a comma, we might be in the middle of an array/object
        // Add a null value to complete the structure
        if last_char == ',' || (last_char == ':' && !in_string) {
            recovered.push_str("null");
        }
        
        // Close structures in reverse order
        while let Some(opener) = structure_stack.pop() {
            match opener {
                '{' => recovered.push('}'),
                '[' => recovered.push(']'),
                _ => {}
            }
        }
        
        // Try to parse the recovered JSON
        match serde_json::from_str(&recovered) {
            Ok(json) => Ok(json),
            Err(_) => {
                // If recovery failed, try a more aggressive approach
                // Find the last complete value and truncate there
                if let Some(last_complete) = self.find_last_complete_value(truncated_json) {
                    serde_json::from_str(&last_complete)
                } else {
                    serde_json::from_str(&recovered)
                }
            }
        }
    }
    
    /// Find the last complete JSON value in a truncated string
    fn find_last_complete_value(&self, truncated_json: &str) -> Option<String> {
        // Try to find common JSON structure endings
        let possible_endings = vec![
            "}]}", "}]", "]}", "}", "]", "\"}\"", "\"]\"", "\"}"
        ];
        
        for ending in possible_endings {
            if let Some(pos) = truncated_json.rfind(ending) {
                let candidate = &truncated_json[..pos + ending.len()];
                if serde_json::from_str::<JsonValue>(candidate).is_ok() {
                    return Some(candidate.to_string());
                }
            }
        }
        
        None
    }

    /// Execute Perceive phase - analyze input and extract entities using structured output
    /// 
    /// This demonstrates the integration pattern with PerceptionAgent using structured output.
    /// In production, this would use:
    /// - PerceptionAgent.analyze_pre_response(chat_history, current_message, user_id, session_dek)
    /// - Proper session management and entity caching
    /// - Direct integration with the agent's structured output types
    pub async fn execute_perceive_phase(
        &self,
        context: &ReasoningContext,
        payload: &EnrichmentTaskPayload,
    ) -> Result<PerceptionResult, OrchestratorError> {
        info!("Executing Perceive phase for task {} - Using structured output pattern", context.task_id);
        
        // Progressive Response: Full analysis for first message, delta for subsequent
        if context.is_first_message {
            self.perceive_full_analysis_structured(context, payload).await
        } else {
            self.perceive_delta_analysis_structured(context, payload).await
        }
    }

    async fn perceive_full_analysis_structured(
        &self,
        _context: &ReasoningContext,
        payload: &EnrichmentTaskPayload,
    ) -> Result<PerceptionResult, OrchestratorError> {
        // This demonstrates the structured output pattern that would integrate with PerceptionAgent
        let schema = get_perception_phase_schema();
        
        let prompt = format!(
            r#"Analyze this roleplay interaction and extract entities, locations, temporal context, and narrative significance.

User message: {}
AI response: {}

Extract:
- All entities mentioned (characters, items, creatures)
- All locations referenced
- Temporal context (time of day, season, etc.) if mentioned
- Narrative significance score from 0.0 to 1.0
- For first message, world_state_delta should be null"#,
            payload.user_message, payload.ai_response
        );

        let analysis = self.analyze_with_structured_output(&prompt, schema).await?;
        
        // Parse into structured output type
        let structured_output: PerceptionPhaseOutput = serde_json::from_value(analysis)
            .map_err(|e| OrchestratorError::ReasoningError(format!("Failed to parse perception output: {}", e)))?;
        
        // Validate the structured output
        structured_output.validate()
            .map_err(|e| OrchestratorError::ReasoningError(format!("Perception validation failed: {}", e)))?;
        
        // Convert to internal type
        structured_output.to_perception_result()
            .map_err(|e| OrchestratorError::ReasoningError(format!("Failed to convert perception result: {}", e)))
    }

    async fn perceive_delta_analysis_structured(
        &self,
        context: &ReasoningContext,
        payload: &EnrichmentTaskPayload,
    ) -> Result<PerceptionResult, OrchestratorError> {
        let cached_state = context.cached_world_state.as_ref()
            .ok_or_else(|| OrchestratorError::ReasoningError("No cached state for delta analysis".to_string()))?;

        let schema = get_perception_phase_schema();
        
        let prompt = format!(
            r#"Analyze changes in this roleplay interaction compared to the cached world state.

Cached state: {}
User message: {}
AI response: {}

Extract:
- All entities mentioned (characters, items, creatures)
- All locations referenced  
- Temporal context if mentioned
- Narrative significance score from 0.0 to 1.0
- For delta analysis, include world_state_delta with analysis_type: "delta""#,
            cached_state, payload.user_message, payload.ai_response
        );

        let analysis = self.analyze_with_structured_output(&prompt, schema).await?;
        
        // Parse into structured output type
        let mut structured_output: PerceptionPhaseOutput = serde_json::from_value(analysis)
            .map_err(|e| OrchestratorError::ReasoningError(format!("Failed to parse perception delta output: {}", e)))?;
        
        // Ensure we have a delta for delta analysis
        if structured_output.world_state_delta.is_none() {
            structured_output.world_state_delta = Some(serde_json::json!({
                "analysis_type": "delta",
                "entities_changed": structured_output.entities_extracted,
                "locations_changed": structured_output.locations_identified
            }));
        }
        
        // Validate the structured output
        structured_output.validate()
            .map_err(|e| OrchestratorError::ReasoningError(format!("Perception delta validation failed: {}", e)))?;
        
        // Convert to internal type
        structured_output.to_perception_result()
            .map_err(|e| OrchestratorError::ReasoningError(format!("Failed to convert perception delta result: {}", e)))
    }

    /// Execute Strategize phase - establish goals and narrative context
    /// 
    /// NOTE: This demonstrates the integration pattern with StrategicAgent.
    /// In production, this would use:
    /// - StrategicAgent.analyze_conversation(chat_history, user_id, session_id, session_dek)
    /// - Proper conversation history loading and strategic directive generation
    /// - Integration with Redis caching for strategic directives
    pub async fn execute_strategize_phase(
        &self,
        context: &ReasoningContext,
        perception: &PerceptionResult,
    ) -> Result<StrategyResult, OrchestratorError> {
        info!("Executing Strategize phase for task {} - Pattern: StrategicAgent Integration", context.task_id);

        // TODO: Replace with StrategicAgent.analyze_conversation()
        // This shows the pattern that would integrate with:
        // self.strategic_agent.analyze_conversation(chat_history, user_id, session_id, session_dek)
        
        let schema = get_strategy_phase_schema();
        
        let prompt = format!(
            r#"Based on the perception analysis, develop a strategy for world enrichment.

Entities: {:?}
Locations: {:?}
Temporal: {:?}
Significance: {}

Determine:
- Primary enrichment goals
- Narrative threads to develop
- World state implications
- Alternative narrative paths"#,
            perception.entities_extracted,
            perception.locations_identified,
            perception.temporal_context,
            perception.narrative_significance
        );

        let strategy = self.analyze_with_structured_output(&prompt, schema).await?;

        Ok(StrategyResult {
            primary_goals: extract_string_array(&strategy, "primary_goals"),
            narrative_threads: extract_string_array(&strategy, "narrative_threads"),
            world_state_implications: strategy.get("implications")
                .cloned()
                .unwrap_or_else(|| json!({
                    "entities": perception.entities_extracted,
                    "locations": perception.locations_identified,
                    "narrative_significance": perception.narrative_significance,
                })),
            alternative_paths: strategy.get("alternative_paths")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()),
        })
    }

    /// Execute Plan phase - create actionable steps
    /// 
    /// NOTE: This demonstrates the integration pattern with TacticalAgent.
    /// In production, this would use:
    /// - TacticalAgent.process_directive(directive, user_id, session_dek)
    /// - Proper strategic directive from the Strategize phase
    /// - Integration with PlanningService for context enrichment
    pub async fn execute_plan_phase(
        &self,
        context: &ReasoningContext,
        strategy: &StrategyResult,
    ) -> Result<PlanResult, OrchestratorError> {
        info!("Executing Plan phase for task {} - Pattern: TacticalAgent Integration", context.task_id);

        // TODO: Replace with TacticalAgent.process_directive()
        // This shows the pattern that would integrate with:
        // self.tactical_agent.process_directive(strategic_directive, user_id, session_dek)
        
        let schema = get_plan_phase_schema();
        
        let prompt = format!(
            r#"Create an execution plan based on the strategy. Be EXTREMELY CONCISE - limit to 3-5 most critical actions only.

Goals: {:?}
Narrative threads: {:?}
Implications: {}

Available tools: {:?}

Generate:
- Concrete action steps (MAXIMUM 5 steps, focus ONLY on most critical actions)
- Minimal dependency graph (only if actions depend on each other)
- Tool selections as a simple array (e.g., [{{"action_name": "CreateEntity", "tool_name": "create_entity"}}])
- OMIT cache optimization hints unless absolutely critical

CRITICAL INSTRUCTIONS:
- Keep ALL descriptions under 20 words
- NO verbose explanations
- Focus on ESSENTIAL actions only
- Prioritize quality over quantity
- If chronicle_id is mentioned in context, include it in relevant tool parameters"#,
            strategy.primary_goals.iter().take(3).collect::<Vec<_>>(), // Limit goals
            strategy.narrative_threads.iter().take(2).collect::<Vec<_>>(), // Limit threads
            strategy.world_state_implications,
            UnifiedToolRegistry::list_all_tool_names().iter().take(10).collect::<Vec<_>>() // Limit tools shown
        );

        let plan = self.analyze_with_structured_output(&prompt, schema).await?;

        // Parse the AI response into the structured output type
        let plan_output: crate::services::orchestrator::structured_output::PlanPhaseOutput = 
            serde_json::from_value(plan)
                .map_err(|e| OrchestratorError::ReasoningError(
                    format!("Failed to parse plan phase output: {}", e)
                ))?;

        // Validate the output
        plan_output.validate()
            .map_err(|e| OrchestratorError::ReasoningError(e.to_string()))?;

        // Convert to PlanResult
        plan_output.to_plan_result()
            .map_err(|e| OrchestratorError::ReasoningError(e.to_string()))
    }

    /// Execute Execute phase - run tools and agents
    pub async fn execute_execute_phase(
        &self,
        context: &ReasoningContext,
        plan: &PlanResult,
    ) -> Result<ExecutionResult, OrchestratorError> {
        info!("Executing Execute phase for task {}", context.task_id);

        let mut executed_actions = Vec::new();
        let mut world_state_changes = json!({});
        let mut errors = Vec::new();
        let mut cache_updates = Vec::new();

        // Execute each action step
        for (idx, action) in plan.action_steps.iter().enumerate() {
            match self.execute_single_action(context, action, &plan.tool_selections).await {
                Ok(result) => {
                    executed_actions.push(json!({
                        "action": action,
                        "success": true,
                        "result": result
                    }));
                    
                    // Track state changes
                    if let Some(changes) = result.get("state_changes") {
                        merge_json_objects(&mut world_state_changes, changes);
                    }
                    
                    // Track cache updates
                    if let Some(cache) = result.get("cache_update").and_then(|v| v.as_str()) {
                        cache_updates.push(cache.to_string());
                    }
                }
                Err(e) => {
                    warn!("Action {} failed: {}", idx, e);
                    executed_actions.push(json!({
                        "action": action,
                        "success": false,
                        "error": e.to_string()
                    }));
                    errors.push(format!("Action {}: {}", idx, e));
                }
            }
        }

        Ok(ExecutionResult {
            executed_actions,
            world_state_changes,
            cache_updates: if cache_updates.is_empty() { None } else { Some(cache_updates) },
            errors,
        })
    }

    async fn execute_single_action(
        &self,
        _context: &ReasoningContext,
        action: &JsonValue,
        tool_selections: &HashMap<String, String>,
    ) -> Result<JsonValue, OrchestratorError> {
        let action_name = action.get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| OrchestratorError::ToolExecutionError {
                tool: "unknown".to_string(),
                error: "No action name specified".to_string(),
            })?;

        let tool_name = tool_selections.get(action_name)
            .ok_or_else(|| OrchestratorError::ToolExecutionError {
                tool: action_name.to_string(),
                error: "No tool selected for action".to_string(),
            })?;

        // Mock tool execution for now
        // In production, this would call actual tools through the registry
        debug!("Executing tool {} for action {}", tool_name, action_name);
        
        Ok(json!({
            "tool": tool_name,
            "action": action_name,
            "state_changes": action.get("params").cloned().unwrap_or_else(|| json!({})),
            "cache_update": format!("{}_cache", action_name)
        }))
    }

    /// Execute Reflect phase - verify completion and update caches
    /// 
    /// NOTE: This demonstrates the integration pattern with PerceptionAgent.
    /// In production, this would use:
    /// - PerceptionAgent.process_ai_response(ai_response, context, user_id, session_dek)
    /// - Proper entity state updates and world state synchronization
    /// - Integration with the progressive cache layers
    pub async fn execute_reflect_phase(
        &self,
        context: &ReasoningContext,
        execution: &ExecutionResult,
        original_goals: &[String],
    ) -> Result<ReflectionResult, OrchestratorError> {
        info!("Executing Reflect phase for task {} - Pattern: PerceptionAgent Post-Response Integration", context.task_id);

        // TODO: Replace with PerceptionAgent.process_ai_response()
        // This shows the pattern that would integrate with:
        // self.perception_agent.process_ai_response(ai_response, enriched_context, user_id, session_dek)
        
        let schema = get_reflection_phase_schema();
        
        let prompt = format!(
            r#"Reflect on the execution results and determine completion status.

Original goals: {:?}
Executed actions: {}
State changes: {}
Errors: {:?}

Determine:
- Which goals were completed
- Which goals remain
- Whether replanning is needed
- Performance assessment"#,
            original_goals,
            serde_json::to_string_pretty(&execution.executed_actions).unwrap_or_default(),
            execution.world_state_changes,
            execution.errors
        );

        let reflection = self.analyze_with_structured_output(&prompt, schema).await?;

        let goals_completed = extract_string_array(&reflection, "goals_completed");
        let goals_remaining = extract_string_array(&reflection, "goals_remaining");
        let replan_needed = reflection.get("replan_needed")
            .and_then(|v| v.as_bool())
            .unwrap_or(!goals_remaining.is_empty());

        // Update cache layers based on successful actions
        let cache_layers_updated = if execution.executed_actions.iter()
            .any(|action| action.get("success").and_then(|v| v.as_bool()).unwrap_or(false)) {
            vec![
                "immediate_context".to_string(),
                "enhanced_context".to_string(),
                "full_world_state".to_string(),
            ]
        } else {
            vec!["immediate_context".to_string()]
        };

        Ok(ReflectionResult {
            goals_completed,
            goals_remaining,
            replan_needed,
            cache_layers_updated,
            performance_metrics: PerformanceMetrics {
                total_duration_ms: 100, // Would be tracked in production
                phase_durations: HashMap::new(),
                cache_hits: 0,
                cache_misses: 0,
                tool_calls: execution.executed_actions.len() as u32,
            },
        })
    }
}

// Helper functions
fn extract_string_array(json: &JsonValue, field: &str) -> Vec<String> {
    json.get(field)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect())
        .unwrap_or_default()
}

fn merge_json_objects(base: &mut JsonValue, updates: &JsonValue) {
    if let (Some(base_obj), Some(updates_obj)) = (base.as_object_mut(), updates.as_object()) {
        for (key, value) in updates_obj {
            base_obj.insert(key.clone(), value.clone());
        }
    }
}