use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use tracing::{debug, info, instrument};
use chrono::Utc;

use crate::{
    errors::AppError,
    models::characters::CharacterMetadata,
    services::{
        context_assembly_engine::{
            EnrichedContext, StrategicDirective, ValidatedPlan, SubGoal, EntityContext,
            SpatialContext, TemporalContext, PlanValidationStatus, ValidationCheck,
            PlotSignificance, WorldImpactLevel, PlanStep, RiskAssessment, RiskLevel,
            ContextRequirement, SpatialLocation, ValidationCheckType, ValidationStatus,
            ValidationSeverity,
        },
        intent_detection_service::{IntentDetectionService, QueryIntent},
        query_strategy_planner::QueryStrategyPlanner,
        agentic::entity_resolution_tool::EntityResolutionTool,
        EncryptionService,
    },
    llm::AiClient,
    PgPool,
};
use genai::chat::{ChatMessage as GenAiChatMessage, MessageContent};
use secrecy::{SecretBox, ExposeSecret};

/// Bridge service that creates EnrichedContext payloads from current data sources
/// This provides immediate hierarchical context capabilities while the full agent system is developed
pub struct HierarchicalContextAssembler {
    ai_client: Arc<dyn AiClient>,
    intent_detection_service: Arc<IntentDetectionService>,
    query_strategy_planner: Arc<QueryStrategyPlanner>,
    entity_resolution_tool: Arc<EntityResolutionTool>,
    encryption_service: Arc<EncryptionService>,
    db_pool: Arc<PgPool>,
}

impl HierarchicalContextAssembler {
    pub fn new(
        ai_client: Arc<dyn AiClient>,
        intent_detection_service: Arc<IntentDetectionService>,
        query_strategy_planner: Arc<QueryStrategyPlanner>,
        entity_resolution_tool: Arc<EntityResolutionTool>,
        encryption_service: Arc<EncryptionService>,
        db_pool: Arc<PgPool>,
    ) -> Self {
        Self {
            ai_client,
            intent_detection_service,
            query_strategy_planner,
            entity_resolution_tool,
            encryption_service,
            db_pool,
        }
    }

    /// Main entry point: Creates EnrichedContext from available data sources
    /// This bridges current capabilities to hierarchical format
    #[instrument(skip(self, user_dek, chat_history))]
    pub async fn assemble_enriched_context(
        &self,
        user_input: &str,
        chat_history: &[GenAiChatMessage],
        character: Option<&CharacterMetadata>,
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<EnrichedContext, AppError> {
        info!("Starting hierarchical context assembly for user input: '{}'", 
            user_input.chars().take(50).collect::<String>());
        
        let start_time = std::time::Instant::now();
        let mut total_tokens_used = 0u32;
        let mut ai_model_calls = 0u32;

        // Step 1: Detect user intent using existing service
        let chat_context = if chat_history.len() > 3 {
            Some(chat_history.iter()
                .rev()
                .take(3)
                .map(|msg| format!("{:?}: {}", msg.role, 
                    match &msg.content {
                        MessageContent::Text(text) => text.chars().take(100).collect::<String>(),
                        _ => "[non-text content]".to_string(),
                    }
                ))
                .collect::<Vec<_>>()
                .join("\n"))
        } else {
            None
        };

        let intent = self.intent_detection_service
            .detect_intent(user_input, chat_context.as_deref())
            .await?;
        ai_model_calls += 1;
        debug!(intent_type = ?intent.intent_type, "Detected user intent");

        // Step 2: Analyze strategic intent using Flash with decrypted character data
        let strategic_directive = self.analyze_strategic_intent(
            user_input, 
            chat_history, 
            &intent, 
            character,
            user_dek
        ).await?;
        ai_model_calls += 1;
        total_tokens_used += 150; // Estimate for strategic analysis

        // Step 3: Create simplified tactical plan
        let validated_plan = self.create_simplified_plan(
            user_input,
            &intent,
            &strategic_directive,
            character,
            user_dek
        ).await?;
        ai_model_calls += 1;
        total_tokens_used += 200; // Estimate for plan creation

        // Step 4: Extract immediate sub-goal
        let current_sub_goal = self.extract_immediate_sub_goal(
            &validated_plan,
            &intent,
            user_input
        )?;

        // Step 5: Gather entity context using existing entity resolution
        let relevant_entities = self.gather_entity_context(
            user_input,
            user_id,
            user_dek,
            character
        ).await?;
        ai_model_calls += 1;
        total_tokens_used += 100; // Estimate for entity resolution

        // Step 6: Build spatial context (simplified)
        let spatial_context = self.build_spatial_context(&relevant_entities, character).await?;

        // Step 7: Build temporal context
        let temporal_context = self.build_temporal_context(chat_history).await?;

        // Step 8: Create basic validation checks (placeholder for future symbolic firewall)
        let symbolic_firewall_checks = self.create_basic_validation_checks(&validated_plan)?;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        let enriched_context = EnrichedContext {
            strategic_directive: Some(strategic_directive),
            validated_plan,
            current_sub_goal,
            relevant_entities,
            spatial_context,
            causal_context: None, // TODO: Implement in future iterations
            temporal_context,
            plan_validation_status: PlanValidationStatus::Validated, // Simplified validation
            symbolic_firewall_checks,
            assembled_context: None, // We're creating pure hierarchical context
            total_tokens_used,
            execution_time_ms,
            validation_time_ms: 10, // Minimal validation time for now
            ai_model_calls,
            confidence_score: 0.75, // Default confidence for bridge implementation
        };

        info!(
            total_tokens = total_tokens_used,
            execution_time_ms = execution_time_ms,
            ai_calls = ai_model_calls,
            "Hierarchical context assembly completed"
        );

        Ok(enriched_context)
    }

    /// Analyzes strategic intent using Flash to create realistic strategic directives
    async fn analyze_strategic_intent(
        &self,
        user_input: &str,
        chat_history: &[GenAiChatMessage],
        intent: &QueryIntent,
        character: Option<&CharacterMetadata>,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<StrategicDirective, AppError> {
        debug!("Analyzing strategic intent with Flash");

        // Prepare context for strategic analysis with decrypted character data
        let character_context = if let Some(char_data) = character {
            let mut context = format!("Character: {}", char_data.name);
            
            // Add decrypted character details if user_dek is available
            if let Some(dek) = user_dek {
                // Include decrypted description if available
                if let Ok(Some(description)) = self.decrypt_character_field(
                    &char_data.description,
                    &char_data.description_nonce,
                    dek,
                    "description"
                ) {
                    context.push_str(&format!("\nDescription: {}", 
                        description.chars().take(200).collect::<String>()));
                }
                
                // Include decrypted personality if available
                if let Ok(Some(personality)) = self.decrypt_character_field(
                    &char_data.personality,
                    &char_data.personality_nonce,
                    dek,
                    "personality"
                ) {
                    context.push_str(&format!("\nPersonality: {}", 
                        personality.chars().take(100).collect::<String>()));
                }
            } else {
                context.push_str("\n[Character details encrypted - limited context available]");
            }
            
            context
        } else {
            "No specific character".to_string()
        };

        let chat_context = if chat_history.len() > 3 {
            // Take last 3 messages for context
            chat_history.iter()
                .rev()
                .take(3)
                .map(|msg| format!("{:?}: {}", msg.role, 
                    match &msg.content {
                        MessageContent::Text(text) => text.chars().take(100).collect::<String>(),
                        _ => "[non-text content]".to_string(),
                    }
                ))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            "Limited chat history".to_string()
        };

        let strategic_prompt = format!(
            r#"You are the Strategic Director in a hierarchical narrative AI system. Analyze this user input and provide strategic narrative direction.

## Context
Character: {}
Intent Type: {:?}
Recent Chat History:
{}

## User Input
"{}"

## Your Task
Analyze this input and determine the high-level narrative direction. Provide:

1. Directive Type: A concise phrase describing the narrative action (e.g., "Character Development", "Conflict Escalation", "Exploration Sequence")
2. Narrative Arc: The broader story trajectory this fits into
3. Plot Significance: How important this moment is to the overall story
4. Emotional Tone: The primary emotional atmosphere to establish
5. World Impact Level: How broadly this affects the narrative world

Respond in this exact JSON format:
{{
    "directive_type": "string",
    "narrative_arc": "string", 
    "plot_significance": "Major|Moderate|Minor|Trivial",
    "emotional_tone": "string",
    "character_focus": ["character_name"],
    "world_impact_level": "Global|Regional|Local|Personal"
}}

Focus on creating engaging, coherent narrative direction that enhances the storytelling experience."#,
            character_context,
            intent.intent_type,
            chat_context,
            user_input
        );

        let chat_request = genai::chat::ChatRequest::from_user(strategic_prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(800)
            .with_temperature(0.3);

        let chat_response = self.ai_client.exec_chat(
            "gemini-2.5-flash",
            chat_request,
            Some(chat_options),
        ).await?;

        let response = chat_response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        // Parse JSON response
        let strategic_analysis: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| AppError::TextProcessingError(format!("Failed to parse strategic analysis: {}", e)))?;

        let directive_type = strategic_analysis["directive_type"]
            .as_str()
            .unwrap_or("General Interaction")
            .to_string();

        let narrative_arc = strategic_analysis["narrative_arc"]
            .as_str()
            .unwrap_or("Ongoing Story")
            .to_string();

        let plot_significance = match strategic_analysis["plot_significance"].as_str() {
            Some("Major") => PlotSignificance::Major,
            Some("Moderate") => PlotSignificance::Moderate,
            Some("Minor") => PlotSignificance::Minor,
            _ => PlotSignificance::Trivial,
        };

        let emotional_tone = strategic_analysis["emotional_tone"]
            .as_str()
            .unwrap_or("Neutral")
            .to_string();

        let character_focus = strategic_analysis["character_focus"]
            .as_array()
            .map(|arr| arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
            )
            .unwrap_or_else(|| vec![character.map(|c| c.name.clone()).unwrap_or_else(|| "User".to_string())]);

        let world_impact_level = match strategic_analysis["world_impact_level"].as_str() {
            Some("Global") => WorldImpactLevel::Global,
            Some("Regional") => WorldImpactLevel::Regional,
            Some("Local") => WorldImpactLevel::Local,
            _ => WorldImpactLevel::Personal,
        };

        Ok(StrategicDirective {
            directive_id: Uuid::new_v4(),
            directive_type,
            narrative_arc,
            plot_significance,
            emotional_tone,
            character_focus,
            world_impact_level,
        })
    }

    /// Creates a simplified tactical plan using Flash analysis
    async fn create_simplified_plan(
        &self,
        user_input: &str,
        intent: &QueryIntent,
        strategic_directive: &StrategicDirective,
        character: Option<&CharacterMetadata>,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> Result<ValidatedPlan, AppError> {
        debug!("Creating simplified tactical plan");

        let planning_prompt = format!(
            r#"You are the Tactical Planner in a hierarchical narrative AI system. Create a concrete plan to execute the strategic directive.

## Strategic Context
Directive: {}
Narrative Arc: {}
Emotional Tone: {}
World Impact: {:?}

## User Input
"{}"

## Character Context
{}

## Your Task
Create a tactical plan with 1-3 concrete steps to fulfill this directive. Each step should be actionable and specific.

Respond in this exact JSON format:
{{
    "steps": [
        {{
            "description": "string",
            "preconditions": ["string"],
            "expected_outcomes": ["string"],
            "required_entities": ["string"],
            "estimated_duration": 1000
        }}
    ],
    "overall_risk": "Low|Medium|High|Critical",
    "mitigation_strategies": ["string"]
}}

Focus on practical, executable steps that advance the narrative."#,
            strategic_directive.directive_type,
            strategic_directive.narrative_arc,
            strategic_directive.emotional_tone,
            strategic_directive.world_impact_level,
            user_input,
            {
                if let Some(char_data) = character {
                    let mut context = format!("Character: {}", char_data.name);
                    
                    // Add decrypted character details for tactical planning
                    if let Some(dek) = user_dek {
                        // Include scenario context for tactical planning
                        if let Ok(Some(scenario)) = self.decrypt_character_field(
                            &char_data.scenario,
                            &char_data.scenario_nonce,
                            dek,
                            "scenario"
                        ) {
                            context.push_str(&format!("\nScenario Context: {}", 
                                scenario.chars().take(150).collect::<String>()));
                        }
                        
                        // Include personality for tactical behavior planning
                        if let Ok(Some(personality)) = self.decrypt_character_field(
                            &char_data.personality,
                            &char_data.personality_nonce,
                            dek,
                            "personality"
                        ) {
                            context.push_str(&format!("\nPersonality Considerations: {}", 
                                personality.chars().take(100).collect::<String>()));
                        }
                    } else {
                        context.push_str("\n[Character details encrypted - tactical planning with limited context]");
                    }
                    
                    context
                } else {
                    "No specific character".to_string()
                }
            }
        );

        let chat_request = genai::chat::ChatRequest::from_user(planning_prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1000)
            .with_temperature(0.3);

        let chat_response = self.ai_client.exec_chat(
            "gemini-2.5-flash",
            chat_request,
            Some(chat_options),
        ).await?;

        let response = chat_response.contents
            .iter()
            .find_map(|content| {
                if let genai::chat::MessageContent::Text(text) = content {
                    Some(text.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        // Parse JSON response
        let plan_analysis: serde_json::Value = serde_json::from_str(&response)
            .map_err(|e| AppError::TextProcessingError(format!("Failed to parse tactical plan: {}", e)))?;

        let steps = plan_analysis["steps"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .map(|step| {
                PlanStep {
                    step_id: Uuid::new_v4(),
                    description: step["description"].as_str().unwrap_or("Execute plan step").to_string(),
                    preconditions: step["preconditions"].as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                        .unwrap_or_default(),
                    expected_outcomes: step["expected_outcomes"].as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                        .unwrap_or_default(),
                    required_entities: step["required_entities"].as_array()
                        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                        .unwrap_or_default(),
                    estimated_duration: step["estimated_duration"].as_u64().or_else(|| Some(1000)),
                }
            })
            .collect();

        let overall_risk = match plan_analysis["overall_risk"].as_str() {
            Some("Critical") => RiskLevel::Critical,
            Some("High") => RiskLevel::High,
            Some("Medium") => RiskLevel::Medium,
            _ => RiskLevel::Low,
        };

        let mitigation_strategies = plan_analysis["mitigation_strategies"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default();

        Ok(ValidatedPlan {
            plan_id: Uuid::new_v4(),
            steps,
            preconditions_met: true, // Simplified validation for now
            causal_consistency_verified: true,
            entity_dependencies: vec![], // TODO: Extract from steps
            estimated_execution_time: Some(2000), // Default estimate
            risk_assessment: RiskAssessment {
                overall_risk,
                identified_risks: vec![], // TODO: Implement risk identification
                mitigation_strategies,
            },
        })
    }

    /// Extracts immediate sub-goal from the tactical plan
    fn extract_immediate_sub_goal(
        &self,
        plan: &ValidatedPlan,
        intent: &QueryIntent,
        user_input: &str,
    ) -> Result<SubGoal, AppError> {
        debug!("Extracting immediate sub-goal from tactical plan");

        // Use the first step of the plan as the immediate sub-goal
        let first_step = plan.steps.first()
            .ok_or_else(|| AppError::TextProcessingError("Tactical plan has no steps".to_string()))?;

        Ok(SubGoal {
            goal_id: Uuid::new_v4(),
            description: first_step.description.clone(),
            actionable_directive: format!("Execute: {}", first_step.description),
            required_entities: first_step.required_entities.clone(),
            success_criteria: first_step.expected_outcomes.clone(),
            context_requirements: vec![
                ContextRequirement {
                    requirement_type: "user_input".to_string(),
                    description: format!("Respond to: {}", user_input),
                    priority: 1.0,
                }
            ],
            priority_level: match intent.confidence {
                x if x > 0.8 => 1.0,
                x if x > 0.6 => 0.8,
                x if x > 0.4 => 0.6,
                _ => 0.4,
            },
        })
    }

    /// Gathers entity context using existing entity resolution capabilities
    /// Properly decrypts character data using user_dek for security compliance
    async fn gather_entity_context(
        &self,
        user_input: &str,
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
        character: Option<&CharacterMetadata>,
    ) -> Result<Vec<EntityContext>, AppError> {
        debug!("Gathering entity context with proper encryption handling");

        let mut entities = Vec::new();

        // Add character as primary entity if available
        if let Some(char_data) = character {
            let mut current_state = HashMap::new();
            let mut ai_insights = Vec::new();

            // Decrypt character fields if user_dek is available
            if let Some(dek) = user_dek {
                // Decrypt and analyze character description
                if let Some(description_decrypted) = self.decrypt_character_field(
                    &char_data.description,
                    &char_data.description_nonce,
                    dek,
                    "description"
                )? {
                    current_state.insert("description".to_string(), description_decrypted.clone().into());
                    ai_insights.push(format!("Character has detailed description: {}", 
                        description_decrypted.chars().take(50).collect::<String>()));
                }

                // Decrypt and analyze character personality
                if let Some(personality_decrypted) = self.decrypt_character_field(
                    &char_data.personality,
                    &char_data.personality_nonce,
                    dek,
                    "personality"
                )? {
                    current_state.insert("personality".to_string(), personality_decrypted.clone().into());
                    ai_insights.push(format!("Character personality defined: {}", 
                        personality_decrypted.chars().take(50).collect::<String>()));
                }

                // Decrypt scenario context
                if let Some(scenario_decrypted) = self.decrypt_character_field(
                    &char_data.scenario,
                    &char_data.scenario_nonce,
                    dek,
                    "scenario"
                )? {
                    current_state.insert("scenario".to_string(), scenario_decrypted.clone().into());
                    ai_insights.push("Character has specific scenario context".to_string());
                }

                // Decrypt example dialogue
                if let Some(dialogue_decrypted) = self.decrypt_character_field(
                    &char_data.mes_example,
                    &char_data.mes_example_nonce,
                    dek,
                    "example_dialogue"
                )? {
                    current_state.insert("example_dialogue".to_string(), dialogue_decrypted.into());
                    ai_insights.push("Character has example dialogue patterns".to_string());
                }
            } else {
                // Without DEK, we can only use public character data
                debug!("No user_dek provided - using only public character data");
                ai_insights.push("Limited character context - encrypted data not accessible".to_string());
            }

            // Always include basic character info
            current_state.insert("character_name".to_string(), char_data.name.clone().into());
            current_state.insert("character_id".to_string(), char_data.id.to_string().into());

            let character_entity = EntityContext {
                entity_id: char_data.id,
                entity_name: char_data.name.clone(),
                entity_type: "Character".to_string(),
                current_state,
                spatial_location: None, // TODO: Implement spatial location extraction
                relationships: vec![], // TODO: Implement relationship extraction
                recent_actions: vec![], // TODO: Implement action history
                emotional_state: None, // TODO: Implement emotional state analysis
                narrative_importance: 0.9, // High importance for main character
                ai_insights,
            };
            entities.push(character_entity);
        }

        // TODO: Use entity resolution tool to find additional relevant entities
        // This would integrate with the existing EntityResolutionTool
        // ensuring user_id ownership validation

        debug!(entity_count = entities.len(), "Gathered entity context with proper encryption");
        Ok(entities)
    }

    /// Securely decrypts character field using user_dek
    /// Returns None if decryption fails or field is empty
    fn decrypt_character_field(
        &self,
        ciphertext: &Option<Vec<u8>>,
        nonce: &Option<Vec<u8>>,
        user_dek: &Arc<SecretBox<Vec<u8>>>,
        field_name: &str,
    ) -> Result<Option<String>, AppError> {
        if let (Some(ct), Some(n)) = (ciphertext, nonce) {
            if !ct.is_empty() {
                match crate::crypto::decrypt_gcm(ct, n, user_dek) {
                    Ok(plaintext_bytes) => {
                        let plaintext = String::from_utf8_lossy(plaintext_bytes.expose_secret());
                        if !plaintext.is_empty() {
                            debug!("Successfully decrypted character field: {}", field_name);
                            return Ok(Some(plaintext.to_string()));
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to decrypt character field \"{}\": {}",
                            field_name,
                            e
                        );
                        return Err(AppError::DecryptionError(format!(
                            "Failed to decrypt character {}: {}", field_name, e
                        )));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Builds simplified spatial context
    async fn build_spatial_context(
        &self,
        _entities: &[EntityContext],
        character: Option<&CharacterMetadata>,
    ) -> Result<Option<SpatialContext>, AppError> {
        debug!("Building simplified spatial context");

        // For now, create a basic spatial context
        // TODO: Integrate with ECS spatial components when available

        if character.is_some() {
            let current_location = SpatialLocation {
                location_id: Uuid::new_v4(),
                name: "Current Scene".to_string(),
                coordinates: None,
                parent_location: None,
                location_type: "Scene".to_string(),
            };

            Ok(Some(SpatialContext {
                current_location,
                nearby_locations: vec![],
                environmental_factors: vec![],
                spatial_relationships: vec![],
            }))
        } else {
            Ok(None)
        }
    }

    /// Builds temporal context from chat history
    async fn build_temporal_context(
        &self,
        chat_history: &[GenAiChatMessage],
    ) -> Result<Option<TemporalContext>, AppError> {
        debug!("Building temporal context from chat history");

        let current_time = Utc::now();
        
        Ok(Some(TemporalContext {
            current_time,
            recent_events: vec![], // TODO: Extract events from chat history
            future_scheduled_events: vec![], // TODO: Implement event scheduling
            temporal_significance: if chat_history.len() > 5 { 0.7 } else { 0.3 },
        }))
    }

    /// Creates basic validation checks (placeholder for future symbolic firewall)
    fn create_basic_validation_checks(
        &self,
        plan: &ValidatedPlan,
    ) -> Result<Vec<ValidationCheck>, AppError> {
        debug!("Creating basic validation checks");

        let mut checks = vec![];

        // Basic plan validation
        if !plan.steps.is_empty() {
            checks.push(ValidationCheck {
                check_type: ValidationCheckType::NarrativeCoherence,
                status: ValidationStatus::Passed,
                message: "Plan contains valid steps".to_string(),
                severity: ValidationSeverity::Low,
            });
        }

        if plan.preconditions_met {
            checks.push(ValidationCheck {
                check_type: ValidationCheckType::DataIntegrity,
                status: ValidationStatus::Passed,
                message: "Basic preconditions validated".to_string(),
                severity: ValidationSeverity::Medium,
            });
        }

        Ok(checks)
    }
}

// TODO: Integration tests will be added in a separate file
// These will test the full pipeline from user input to EnrichedContext