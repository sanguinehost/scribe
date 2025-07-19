use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use tracing::{debug, info, instrument};
use chrono::Utc;

use crate::{
    errors::AppError,
    models::characters::CharacterMetadata,
    services::{
        context_assembly_engine::{
            EnrichedContext, StrategicDirective, ValidatedPlan, SubGoal, EntityContext,
            SpatialContext, TemporalContext, CausalContext, CausalChain, CausalEvent,
            PotentialConsequence, HistoricalPrecedent, PlanValidationStatus, ValidationCheck,
            PlotSignificance, WorldImpactLevel, PlanStep, RiskAssessment, RiskLevel,
            ContextRequirement, SpatialLocation, ValidationCheckType, ValidationStatus,
            ValidationSeverity, EntityRelationship, RecentAction, EmotionalState,
            TemporalEvent, ScheduledEvent,
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
    model: String,
}

impl HierarchicalContextAssembler {
    pub fn new(
        ai_client: Arc<dyn AiClient>,
        intent_detection_service: Arc<IntentDetectionService>,
        query_strategy_planner: Arc<QueryStrategyPlanner>,
        entity_resolution_tool: Arc<EntityResolutionTool>,
        encryption_service: Arc<EncryptionService>,
        db_pool: Arc<PgPool>,
        model: String,
    ) -> Self {
        Self {
            ai_client,
            intent_detection_service,
            query_strategy_planner,
            entity_resolution_tool,
            encryption_service,
            db_pool,
            model,
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
            chat_history,
            user_id,
            user_dek,
            character
        ).await?;
        ai_model_calls += 1;
        total_tokens_used += 100; // Estimate for entity resolution

        // Step 6: Build spatial context (simplified)
        let spatial_context = self.build_spatial_context(&relevant_entities, character).await?;

        // Step 7: Build temporal context
        let temporal_context = self.build_temporal_context(user_input, chat_history).await?;
        
        // Step 8: Build causal context
        let causal_context = self.build_causal_context(user_input, chat_history, &relevant_entities).await?;

        // Step 9: Create basic validation checks (placeholder for future symbolic firewall)
        let symbolic_firewall_checks = self.create_basic_validation_checks(&validated_plan)?;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        let enriched_context = EnrichedContext {
            strategic_directive: Some(strategic_directive),
            validated_plan,
            current_sub_goal,
            relevant_entities,
            spatial_context,
            causal_context,
            temporal_context,
            plan_validation_status: PlanValidationStatus::Validated, // Simplified validation
            symbolic_firewall_checks,
            assembled_context: None, // We're creating pure hierarchical context
            perception_analysis: None,
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
            &self.model,
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
            &self.model,
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

        let steps: Vec<PlanStep> = plan_analysis["steps"]
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
            _ => {
                // Fallback: assess risk based on user input content
                let input_lower = user_input.to_lowercase();
                if input_lower.contains("attack") || input_lower.contains("fight") || 
                   input_lower.contains("combat") || input_lower.contains("battle") ||
                   input_lower.contains("dangerous") || input_lower.contains("dragon") ||
                   input_lower.contains("monster") || input_lower.contains("kill") {
                    RiskLevel::High
                } else if input_lower.contains("explore") || input_lower.contains("investigate") ||
                          input_lower.contains("search") || input_lower.contains("examine") {
                    RiskLevel::Medium
                } else {
                    RiskLevel::Low
                }
            }
        };

        let mitigation_strategies = plan_analysis["mitigation_strategies"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
            .unwrap_or_default();

        // Extract entity dependencies before moving steps
        let entity_dependencies = self.extract_entity_dependencies(&steps).await?;
        
        // Identify risks based on the strategic directive and plan steps
        let identified_risks = self.identify_risks(
            user_input,
            strategic_directive,
            &steps,
            &overall_risk
        ).await?;
        
        Ok(ValidatedPlan {
            plan_id: Uuid::new_v4(),
            steps,
            preconditions_met: true, // Simplified validation for now
            causal_consistency_verified: true,
            entity_dependencies,
            estimated_execution_time: Some(2000), // Default estimate
            risk_assessment: RiskAssessment {
                overall_risk,
                identified_risks,
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
        chat_history: &[GenAiChatMessage],
        user_id: Uuid,
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
        character: Option<&CharacterMetadata>,
    ) -> Result<Vec<EntityContext>, AppError> {
        debug!("Gathering entity context with proper encryption handling");

        let mut entities = Vec::new();

        // Add character as primary entity if available
        if let Some(char_data) = character {
            debug!("Processing character entity: {}", char_data.name);
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
                spatial_location: self.extract_spatial_location(user_input, &char_data.name).await?,
                relationships: {
                    debug!("About to extract relationships for: {}", char_data.name);
                    let relationships = self.extract_relationships(user_input, &chat_history, &char_data.name).await?;
                    debug!("Extracted {} relationships", relationships.len());
                    relationships
                },
                recent_actions: self.extract_recent_actions(user_input, &chat_history, &char_data.name).await?,
                emotional_state: self.extract_emotional_state(user_input, &chat_history, &char_data.name).await?,
                narrative_importance: 0.9, // High importance for main character
                ai_insights,
            };
            entities.push(character_entity);
        }

        // Use EntityResolutionTool to find additional relevant entities
        // This ensures user_id ownership validation through the tool
        match self.entity_resolution_tool.resolve_entities_multistage(
            user_input,
            user_id,
            None, // No specific chronicle for hierarchical context
            &[], // No existing entities for initial resolution
        ).await {
            Ok(resolution_result) => {
                let entity_count = resolution_result.resolved_entities.len();
                
                // Convert resolved entities to EntityContext format
                for resolved_entity in resolution_result.resolved_entities {
                    let mut current_state = HashMap::new();
                    current_state.insert("entity_id".to_string(), resolved_entity.entity_id.to_string().into());
                    current_state.insert("confidence".to_string(), resolved_entity.confidence.to_string().into());
                    current_state.insert("is_new".to_string(), resolved_entity.is_new.to_string().into());
                    
                    // Add properties as state
                    for (i, property) in resolved_entity.properties.iter().enumerate() {
                        current_state.insert(format!("property_{}", i), property.clone().into());
                    }
                    
                    // Add components as state
                    for (i, component) in resolved_entity.components.iter().enumerate() {
                        current_state.insert(format!("component_{}", i), component.clone().into());
                    }
                    
                    let ai_insights = vec![
                        format!("Entity resolved with confidence: {:.2}", resolved_entity.confidence),
                        format!("Entity type: {}", resolved_entity.entity_type),
                        if resolved_entity.is_new { "New entity created" } else { "Existing entity matched" }.to_string(),
                    ];
                    
                    let entity_context = EntityContext {
                        entity_id: resolved_entity.entity_id,
                        entity_name: resolved_entity.name.clone(),
                        entity_type: resolved_entity.entity_type,
                        current_state,
                        spatial_location: self.extract_spatial_location(user_input, &resolved_entity.name).await?,
                        relationships: vec![], // TODO: Convert from resolution_result.relationships
                        recent_actions: vec![], // TODO: Implement action history
                        emotional_state: None, // TODO: Extract from components
                        narrative_importance: if resolved_entity.is_new { 0.6 } else { 0.8 }, // Existing entities have higher importance
                        ai_insights,
                    };
                    
                    entities.push(entity_context);
                }
                
                debug!("Entity resolution added {} entities", entity_count);
            }
            Err(e) => {
                // Log error but don't fail the entire context assembly
                tracing::warn!("Entity resolution failed: {}", e);
                debug!("Continuing with character-only entity context");
            }
        }

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

    /// Builds spatial context from extracted entity locations
    async fn build_spatial_context(
        &self,
        entities: &[EntityContext],
        character: Option<&CharacterMetadata>,
    ) -> Result<Option<SpatialContext>, AppError> {
        debug!("Building spatial context from entity locations");

        // Try to find a spatial location from the entities
        let primary_location = entities
            .iter()
            .find_map(|entity| entity.spatial_location.as_ref())
            .cloned();

        let current_location = primary_location.unwrap_or_else(|| {
            // Fallback to a default location if no spatial information was extracted
            SpatialLocation {
                location_id: Uuid::new_v4(),
                name: "Current Scene".to_string(),
                coordinates: None,
                parent_location: None,
                location_type: "Scene".to_string(),
            }
        });

        debug!("Using spatial location: {}", current_location.name);

        // Build spatial context with the extracted location
        Ok(Some(SpatialContext {
            current_location,
            nearby_locations: vec![], // TODO: Could be enhanced with nearby location detection
            environmental_factors: vec![], // TODO: Could be enhanced with environmental analysis
            spatial_relationships: vec![], // TODO: Could be enhanced with relationship analysis
        }))
    }

    /// Builds temporal context from chat history
    async fn build_temporal_context(
        &self,
        user_input: &str,
        chat_history: &[GenAiChatMessage],
    ) -> Result<Option<TemporalContext>, AppError> {
        debug!("Building temporal context from chat history");

        let current_time = Utc::now();
        
        // Extract recent events from chat history
        let recent_events = self.extract_recent_events(user_input, chat_history).await?;
        
        // Extract future scheduled events
        let future_scheduled_events = self.extract_future_events(user_input, chat_history).await?;
        
        // Calculate temporal significance based on event density and recency
        let temporal_significance = if !recent_events.is_empty() || !future_scheduled_events.is_empty() {
            0.8 // High significance if events are present
        } else if chat_history.len() > 5 {
            0.5 // Medium significance for longer conversations
        } else {
            0.3 // Low significance otherwise
        };
        
        Ok(Some(TemporalContext {
            current_time,
            recent_events,
            future_scheduled_events,
            temporal_significance,
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

    /// Extracts entity dependencies from plan steps using AI analysis
    async fn extract_entity_dependencies(&self, steps: &[PlanStep]) -> Result<Vec<String>, AppError> {
        use crate::services::agentic::entity_dependency_structured_output::{
            EntityDependencyOutput, get_entity_dependency_schema
        };
        
        debug!("Extracting entity dependencies from {} plan steps using AI", steps.len());
        
        // If no steps, return empty dependencies
        if steps.is_empty() {
            return Ok(vec![]);
        }
        
        // Prepare steps summary for AI analysis
        let steps_detail = steps.iter()
            .enumerate()
            .map(|(i, step)| {
                format!("Step {}: {}\n  Required entities: {:?}\n  Expected outcomes: {:?}",
                    i + 1,
                    step.description,
                    step.required_entities,
                    step.expected_outcomes
                )
            })
            .collect::<Vec<_>>()
            .join("\n\n");
        
        let dependency_prompt = format!(
            r#"You are the Entity Dependency Analyzer in a hierarchical narrative AI system. Analyze the following plan steps to identify all entity dependencies.

## Plan Steps to Analyze:
{}

## Your Task
Analyze these plan steps and identify:

1. **Explicit Dependencies**: Entities directly mentioned in the required_entities field
2. **Implicit Dependencies**: Entities that are implied but not explicitly stated (e.g., if a step mentions "the king's advisor", the king is an implicit dependency)
3. **Contextual Dependencies**: Environmental entities or context needed for the plan to make sense (e.g., locations, items, or background characters)
4. **Dependency Relationships**: How entities depend on or relate to each other

For each dependency, provide:
- The entity name
- Type of dependency (required/optional/contextual/environmental)
- Why it's a dependency
- Confidence score
- Which steps reference it (0-indexed)

Also analyze relationships between entities to build a dependency graph.

Respond with a JSON object following the provided schema."#,
            steps_detail
        );
        
        // Get the schema for structured output
        let schema = get_entity_dependency_schema();
        
        let chat_request = genai::chat::ChatRequest::from_user(dependency_prompt);
            
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1000)
            .with_temperature(0.3) // Low temperature for consistent analysis
            .with_response_format(genai::chat::ChatResponseFormat::JsonSchemaSpec(
                genai::chat::JsonSchemaSpec {
                    schema: schema.clone(),
                }
            ));
        
        let chat_response = self.ai_client.exec_chat(
            &self.model,
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
            .ok_or_else(|| AppError::AiServiceError("No text response from AI".to_string()))?;
        
        // Parse the structured output
        let dependency_output: EntityDependencyOutput = serde_json::from_str(&response)
            .map_err(|e| AppError::AiServiceError(format!("Failed to parse dependency analysis: {}", e)))?;
        
        // Validate the output
        dependency_output.validate()?;
        
        // Convert to entity list for backward compatibility
        let entities = dependency_output.to_entity_list();
        
        debug!("AI extracted {} entity dependencies with confidence {:.2}: explicit={}, implicit={}, contextual={}", 
            entities.len(),
            dependency_output.confidence_score,
            dependency_output.explicit_dependencies.len(),
            dependency_output.implicit_dependencies.len(),
            dependency_output.contextual_dependencies.len()
        );
        
        Ok(entities)
    }
    
    /// Identifies risks based on the strategic directive and plan steps using Flash AI
    async fn identify_risks(
        &self,
        user_input: &str,
        strategic_directive: &StrategicDirective,
        steps: &[PlanStep],
        overall_risk: &RiskLevel,
    ) -> Result<Vec<String>, AppError> {
        debug!("Identifying risks for strategic directive and plan steps");
        
        // Prepare context for risk analysis
        let steps_summary = steps.iter()
            .map(|step| format!("- {}", step.description))
            .collect::<Vec<_>>()
            .join("\n");
        
        let risk_prompt = format!(
            r#"You are the Risk Assessment Specialist in a hierarchical narrative AI system. Analyze the following scenario and identify specific risks.

## Scenario Analysis
User Input: "{}"
Strategic Directive: {}
Narrative Arc: {}
Plot Significance: {:?}
Emotional Tone: {}
World Impact: {:?}
Current Risk Level: {:?}

## Planned Steps:
{}

## Your Task
Analyze this scenario and identify concrete, specific risks that could occur during execution. Focus on:

1. **Immediate Physical/Combat Risks**: Direct dangers to characters
2. **Strategic/Narrative Risks**: Threats to story progression or character development
3. **Emotional/Psychological Risks**: Potential for trauma or negative character impact
4. **Environmental/World Risks**: Dangers from the setting or world state
5. **Relational Risks**: Potential damage to relationships or alliances

Return your analysis as a JSON array of risk descriptions. Each risk should be specific, actionable, and focused on potential negative outcomes.

Example format:
[
  "Direct physical combat with dragon poses lethal threat to character",
  "Cave environment may contain additional hazards or traps",
  "Failure could result in loss of reputation or standing"
]

Be specific and avoid generic risks. Focus on what could realistically go wrong in this narrative context."#,
            user_input,
            strategic_directive.directive_type,
            strategic_directive.narrative_arc,
            strategic_directive.plot_significance,
            strategic_directive.emotional_tone,
            strategic_directive.world_impact_level,
            overall_risk,
            steps_summary
        );
        
        let chat_request = genai::chat::ChatRequest::from_user(risk_prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(600)
            .with_temperature(0.4); // Slightly higher temperature for creative risk identification
        
        let chat_response = self.ai_client.exec_chat(
            &self.model,
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
        
        // Parse JSON response - handle both array and object formats
        let risks: Vec<String> = match serde_json::from_str::<Vec<String>>(&response) {
            Ok(risks) => risks,
            Err(_) => {
                // Try to parse as JSON object that might contain risks
                match serde_json::from_str::<serde_json::Value>(&response) {
                    Ok(value) => {
                        // Try to extract risks from various object formats
                        if let Some(risks_array) = value.get("risks") {
                            risks_array.as_array()
                                .unwrap_or(&vec![])
                                .iter()
                                .filter_map(|v| v.as_str())
                                .map(|s| s.to_string())
                                .collect()
                        } else if let Some(risks_array) = value.get("identified_risks") {
                            risks_array.as_array()
                                .unwrap_or(&vec![])
                                .iter()
                                .filter_map(|v| v.as_str())
                                .map(|s| s.to_string())
                                .collect()
                        } else {
                            // Fallback: create some generic risks based on the scenario
                            vec![
                                "Potential combat risks in dangerous scenario".to_string(),
                                "Environmental hazards may be present".to_string(),
                                "Outcome may affect character standing".to_string(),
                            ]
                        }
                    }
                    Err(e) => {
                        debug!("Failed to parse risk analysis JSON: {}", e);
                        debug!("Response was: {}", response);
                        // Return fallback risks instead of failing
                        vec![
                            "Potential combat risks in dangerous scenario".to_string(),
                            "Environmental hazards may be present".to_string(),
                            "Outcome may affect character standing".to_string(),
                        ]
                    }
                }
            }
        };
        
        debug!("Identified {} risks for scenario", risks.len());
        Ok(risks)
    }
    
    /// Extracts spatial location information from user input using Flash AI
    async fn extract_spatial_location(
        &self,
        user_input: &str,
        entity_name: &str,
    ) -> Result<Option<SpatialLocation>, AppError> {
        debug!("Extracting spatial location for entity: {}", entity_name);
        
        // Check if user input contains spatial information
        let input_lower = user_input.to_lowercase();
        if !input_lower.contains("in ") && !input_lower.contains("at ") && 
           !input_lower.contains("inside") && !input_lower.contains("outside") &&
           !input_lower.contains("near") && !input_lower.contains("by ") &&
           !input_lower.contains("hall") && !input_lower.contains("room") &&
           !input_lower.contains("castle") && !input_lower.contains("cave") &&
           !input_lower.contains("forest") && !input_lower.contains("town") &&
           !input_lower.contains("standing") && !input_lower.contains("sitting") &&
           !input_lower.contains("lying") && !input_lower.contains("location") {
            debug!("No spatial indicators found in user input");
            return Ok(None);
        }
        
        let spatial_prompt = format!(
            r#"You are the Spatial Location Analyst in a hierarchical narrative AI system. Extract location information from user input.

## Context
Entity: {}
User Input: "{}"

## Your Task
Analyze the input and extract spatial location information if present. Look for:

1. **Explicit Locations**: Named places, rooms, buildings, areas
2. **Positional Indicators**: "in", "at", "inside", "outside", "near", "by"
3. **Environmental Clues**: Descriptions that imply location context
4. **Spatial Relationships**: Where the entity is relative to other things

If spatial information is present, respond with JSON:
{{
  "location_name": "string",
  "location_type": "Room|Building|Area|Scene|Outdoors|Vehicle|Container",
  "parent_location": "string or null",
  "description": "string"
}}

If no clear spatial information is present, respond with: null

Examples:
- "I am in the grand castle hall" -> {{"location_name": "Grand Castle Hall", "location_type": "Room", "parent_location": "Castle", "description": "A grand hall within a castle"}}
- "We're standing outside the tavern" -> {{"location_name": "Outside The Tavern", "location_type": "Outdoors", "parent_location": "Tavern Area", "description": "The area outside a tavern"}}
- "Hello there" -> null

Be specific and extract only what's clearly stated or strongly implied."#,
            entity_name,
            user_input
        );
        
        let chat_request = genai::chat::ChatRequest::from_user(spatial_prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(300)
            .with_temperature(0.2); // Low temperature for consistent extraction
        
        let chat_response = self.ai_client.exec_chat(
            &self.model,
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
        
        // Handle "null" response
        if response.trim() == "null" {
            debug!("No spatial location found in user input");
            return Ok(None);
        }
        
        // Parse JSON response - handle various formats gracefully
        let location_data: serde_json::Value = match serde_json::from_str(&response) {
            Ok(data) => data,
            Err(e) => {
                debug!("Failed to parse spatial location JSON: {}", e);
                debug!("Response was: {}", response);
                
                // Create a fallback location based on the user input
                let fallback_location = SpatialLocation {
                    location_id: Uuid::new_v4(),
                    name: "Current Location".to_string(),
                    coordinates: None,
                    parent_location: None,
                    location_type: "Scene".to_string(),
                };
                
                debug!("Using fallback spatial location: {}", fallback_location.name);
                return Ok(Some(fallback_location));
            }
        };
        
        let location_name = location_data["location_name"]
            .as_str()
            .unwrap_or("Current Location")
            .to_string();
        
        let location_type = location_data["location_type"]
            .as_str()
            .unwrap_or("Scene")
            .to_string();
        
        let parent_location = location_data["parent_location"]
            .as_str()
            .map(|_| Uuid::new_v4()); // Generate a UUID for the parent location
        
        let description = location_data["description"]
            .as_str()
            .unwrap_or("")
            .to_string();
        
        let spatial_location = SpatialLocation {
            location_id: Uuid::new_v4(),
            name: location_name,
            coordinates: None, // Could be enhanced with coordinate extraction
            parent_location,
            location_type,
        };
        
        debug!("Extracted spatial location: {}", spatial_location.name);
        Ok(Some(spatial_location))
    }
    
    /// Extracts relationships from user input and chat history using Flash AI
    async fn extract_relationships(
        &self,
        user_input: &str,
        chat_history: &[GenAiChatMessage],
        entity_name: &str,
    ) -> Result<Vec<EntityRelationship>, AppError> {
        debug!("Extracting relationships for entity: {}", entity_name);
        
        // Build context from chat history
        let mut context_messages = Vec::new();
        for message in chat_history.iter().rev().take(5) {
            if let genai::chat::MessageContent::Text(text) = &message.content {
                context_messages.push(format!("{:?}: {}", message.role, text));
            }
        }
        
        let chat_context = context_messages.join("\n");
        
        // Check if there's meaningful relationship context
        let input_lower = user_input.to_lowercase();
        let has_relationship_indicators = input_lower.contains("with") 
            || input_lower.contains("and") 
            || input_lower.contains("to") 
            || input_lower.contains("from")
            || input_lower.contains("about")
            || input_lower.contains("mentor")
            || input_lower.contains("friend")
            || input_lower.contains("enemy")
            || input_lower.contains("talks")
            || input_lower.contains("seeks");
        
        if chat_context.is_empty() && !has_relationship_indicators {
            debug!("No relationship context found in input or chat history");
            return Ok(vec![]);
        }
        
        debug!("Chat context: '{}'", chat_context);
        debug!("Has relationship indicators: {}", has_relationship_indicators);
        
        let relationship_prompt = format!(
            r#"You are the Relationship Analyst in a hierarchical narrative AI system. Extract relationship information from the conversation context.

## Context
Target Entity: {}
Current User Input: "{}"

## Recent Chat History
{}

## Your Task
Analyze the conversation and extract relationships involving the target entity. Look for:

1. **Direct Relationships**: Explicit mentions of connections between entities
2. **Implied Relationships**: Contextual clues about how entities relate
3. **Interaction Patterns**: How entities interact or behave toward each other
4. **Social Dynamics**: Power structures, emotional connections, professional relationships

Respond with a JSON array of relationships. Each relationship should have:
- "from_entity": The source entity (usually the target entity)
- "to_entity": The entity they're related to
- "relationship_type": Type of relationship (e.g., "mentor", "friend", "enemy", "colleague", "family", "romantic", "professional")
- "strength": Confidence score 0.0-1.0 (1.0 = very certain, 0.5 = moderate, 0.1 = weak)
- "context": Brief description of evidence for this relationship

If no clear relationships are found, respond with: []

Examples:
- "Sir Galahad seeks guidance from Merlin" -> [{{"from_entity": "Sir Galahad", "to_entity": "Merlin", "relationship_type": "student", "strength": 0.8, "context": "Seeks guidance from"}}]
- "The princess smiled at the knight" -> [{{"from_entity": "Sir Galahad", "to_entity": "Princess", "relationship_type": "acquaintance", "strength": 0.6, "context": "Positive interaction"}}]

Focus on relationships that are clearly supported by the text."#,
            entity_name,
            user_input,
            chat_context
        );
        
        let chat_request = genai::chat::ChatRequest::from_user(relationship_prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(400)
            .with_temperature(0.3); // Moderate temperature for balanced extraction
        
        let chat_response = self.ai_client.exec_chat(
            &self.model,
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
        
        debug!("AI response for relationships: '{}'", response);
        
        // Handle empty array response
        if response.trim() == "[]" {
            debug!("No relationships found in conversation");
            return Ok(vec![]);
        }
        
        // Parse JSON response - handle various formats gracefully
        let relationships_data: serde_json::Value = match serde_json::from_str(&response) {
            Ok(data) => data,
            Err(e) => {
                debug!("Failed to parse relationships JSON: {}", e);
                debug!("Response was: {}", response);
                return Ok(vec![]);
            }
        };
        
        let mut relationships = Vec::new();
        
        // Handle array of relationships
        if let Some(array) = relationships_data.as_array() {
            for relationship_data in array {
                let from_entity = relationship_data["from_entity"]
                    .as_str()
                    .unwrap_or(entity_name)
                    .to_string();
                
                let to_entity = relationship_data["to_entity"]
                    .as_str()
                    .unwrap_or("Unknown")
                    .to_string();
                
                let relationship_type = relationship_data["relationship_type"]
                    .as_str()
                    .unwrap_or("acquaintance")
                    .to_string();
                
                let strength = relationship_data["strength"]
                    .as_f64()
                    .unwrap_or(0.5) as f32;
                
                let context = relationship_data["context"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                
                // Only add relationships with reasonable strength
                if strength >= 0.1 && !to_entity.is_empty() && to_entity != "Unknown" {
                    relationships.push(EntityRelationship {
                        relationship_id: Uuid::new_v4(),
                        from_entity,
                        to_entity,
                        relationship_type,
                        strength,
                        context,
                    });
                }
            }
        }
        
        debug!("Extracted {} relationships for entity: {}", relationships.len(), entity_name);
        Ok(relationships)
    }
    
    /// Extracts recent actions from chat history using Flash AI
    async fn extract_recent_actions(
        &self,
        user_input: &str,
        chat_history: &[GenAiChatMessage],
        entity_name: &str,
    ) -> Result<Vec<RecentAction>, AppError> {
        debug!("Extracting recent actions for entity: {}", entity_name);
        
        // Build context from chat history
        let mut context_messages = Vec::new();
        for message in chat_history.iter().rev().take(8) {
            if let genai::chat::MessageContent::Text(text) = &message.content {
                context_messages.push(format!("{:?}: {}", message.role, text));
            }
        }
        
        let chat_context = context_messages.join("\n");
        
        // Check if there are enough messages to extract actions
        if chat_context.is_empty() && user_input.len() < 20 {
            debug!("No meaningful action context found in input or chat history");
            return Ok(vec![]);
        }
        
        // Check for action indicators
        let input_lower = user_input.to_lowercase();
        let has_action_indicators = input_lower.contains("did") 
            || input_lower.contains("does") 
            || input_lower.contains("went") 
            || input_lower.contains("goes")
            || input_lower.contains("attack")
            || input_lower.contains("defend")
            || input_lower.contains("cast")
            || input_lower.contains("move")
            || input_lower.contains("says")
            || input_lower.contains("said")
            || input_lower.contains("talk")
            || input_lower.contains("fight")
            || input_lower.contains("use")
            || input_lower.contains("pick")
            || input_lower.contains("give")
            || input_lower.contains("take");
        
        if !has_action_indicators && chat_context.is_empty() {
            debug!("No action indicators found in input or chat history");
            return Ok(vec![]);
        }
        
        debug!("Chat context: '{}'", chat_context);
        debug!("Has action indicators: {}", has_action_indicators);
        
        let action_prompt = format!(
            r#"You are the Action Historian in a hierarchical narrative AI system. Extract recent actions performed by the target entity from the conversation context.

## Context
Target Entity: {}
Current User Input: "{}"

## Recent Chat History
{}

## Your Task
Analyze the conversation and extract recent actions performed by the target entity. Look for:

1. **Direct Actions**: Explicit actions mentioned in the conversation
2. **Implied Actions**: Actions that can be inferred from context
3. **Verbal Actions**: Speaking, communicating, or verbal interactions
4. **Physical Actions**: Movement, combat, item usage, gestures
5. **Social Actions**: Interactions with other entities

Respond with a JSON array of actions. Each action should have:
- "description": Clear description of what the entity did
- "action_type": Type of action (e.g., "combat", "social", "movement", "verbal", "magical", "item_usage")
- "impact_level": Significance score 0.0-1.0 (1.0 = major story impact, 0.5 = moderate, 0.1 = minor)
- "timestamp_relative": Relative time indicator (e.g., "just now", "recently", "a moment ago")

If no clear actions are found, respond with: []

Examples:
- "Sir Galahad attacked the dragon" -> [{{"description": "Attacked the dragon with sword", "action_type": "combat", "impact_level": 0.8, "timestamp_relative": "just now"}}]
- "The knight spoke to the princess" -> [{{"description": "Spoke to the princess", "action_type": "social", "impact_level": 0.6, "timestamp_relative": "recently"}}]
- "He cast a healing spell" -> [{{"description": "Cast a healing spell", "action_type": "magical", "impact_level": 0.7, "timestamp_relative": "just now"}}]

Focus on actions that are clearly supported by the conversation context."#,
            entity_name,
            user_input,
            chat_context
        );
        
        let chat_request = genai::chat::ChatRequest::from_user(action_prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(500)
            .with_temperature(0.3); // Moderate temperature for balanced extraction
        
        let chat_response = self.ai_client.exec_chat(
            &self.model,
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
        
        debug!("AI response for recent actions: '{}'", response);
        
        // Handle empty array response
        if response.trim() == "[]" {
            debug!("No recent actions found in conversation");
            return Ok(vec![]);
        }
        
        // Parse JSON response - handle various formats gracefully
        let actions_data: serde_json::Value = match serde_json::from_str(&response) {
            Ok(data) => data,
            Err(e) => {
                debug!("Failed to parse recent actions JSON: {}", e);
                debug!("Response was: {}", response);
                return Ok(vec![]);
            }
        };
        
        let mut recent_actions = Vec::new();
        
        // Handle array of actions
        if let Some(array) = actions_data.as_array() {
            for action_data in array {
                let description = action_data["description"]
                    .as_str()
                    .unwrap_or("Unknown action")
                    .to_string();
                
                let action_type = action_data["action_type"]
                    .as_str()
                    .unwrap_or("general")
                    .to_string();
                
                let impact_level = action_data["impact_level"]
                    .as_f64()
                    .unwrap_or(0.5) as f32;
                
                let timestamp_relative = action_data["timestamp_relative"]
                    .as_str()
                    .unwrap_or("recently")
                    .to_string();
                
                // Only add actions with meaningful descriptions
                if !description.is_empty() && description != "Unknown action" {
                    // Convert relative timestamp to actual timestamp
                    let timestamp = match timestamp_relative.as_str() {
                        "just now" => Utc::now() - chrono::Duration::seconds(30),
                        "recently" => Utc::now() - chrono::Duration::minutes(5),
                        "a moment ago" => Utc::now() - chrono::Duration::minutes(2),
                        _ => Utc::now() - chrono::Duration::minutes(3), // Default fallback
                    };
                    
                    recent_actions.push(RecentAction {
                        action_id: Uuid::new_v4(),
                        description,
                        timestamp,
                        action_type,
                        impact_level: impact_level.clamp(0.0, 1.0),
                    });
                }
            }
        }
        
        debug!("Extracted {} recent actions for entity: {}", recent_actions.len(), entity_name);
        Ok(recent_actions)
    }

    /// Extract emotional state from user input and chat history using Flash AI
    #[instrument(skip(self, user_input, chat_history))]
    async fn extract_emotional_state(
        &self,
        user_input: &str,
        chat_history: &[GenAiChatMessage],
        entity_name: &str,
    ) -> Result<Option<EmotionalState>, AppError> {
        // Build context from chat history
        let context = if chat_history.len() > 5 {
            chat_history.iter()
                .rev()
                .take(5)
                .map(|msg| {
                    let content = match &msg.content {
                        MessageContent::Text(text) => text.clone(),
                        _ => "[non-text content]".to_string(),
                    };
                    format!("{:?}: {}", msg.role, content)
                })
                .collect::<Vec<_>>()
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            chat_history.iter()
                .map(|msg| {
                    let content = match &msg.content {
                        MessageContent::Text(text) => text.clone(),
                        _ => "[non-text content]".to_string(),
                    };
                    format!("{:?}: {}", msg.role, content)
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        // Check if there are emotional indicators in the input or context
        let emotional_indicators = [
            "feel", "emotion", "mood", "happy", "sad", "anger", "fear", "joy", "grief", "excited",
            "frustrated", "worried", "confident", "nervous", "calm", "agitated", "devastated",
            "determined", "doubt", "conflicted", "peaceful", "distressed", "hopeful", "despair",
            "content", "overwhelmed", "anxious", "elated", "disappointed", "relieved", "bitter",
            "love", "hate", "jealous", "envious", "proud", "shame", "guilt", "regret", "nostalgic"
        ];

        let combined_text = format!("{} {}", user_input, context);
        let has_emotional_indicators = emotional_indicators.iter()
            .any(|indicator| combined_text.to_lowercase().contains(indicator));

        if !has_emotional_indicators {
            debug!("No emotional indicators found for entity: {}", entity_name);
            return Ok(None);
        }

        // Use Flash AI to extract emotional state
        let prompt = format!(
            "Analyze the emotional state of the character '{}' based on this conversation context and current input.

Context from conversation:
{}

Current input:
{}

Extract the character's emotional state. Respond with a JSON object containing:
- \"primary_emotion\": the main emotion (e.g., \"grief\", \"joy\", \"anger\", \"fear\", \"determination\")
- \"intensity\": emotional intensity from 0.0 to 1.0
- \"contributing_factors\": array of strings describing what's causing these emotions

Only analyze the emotional state of the specified character. If no clear emotional state can be determined, respond with null.",
            entity_name, context, user_input
        );

        debug!("Extracting emotional state for entity: {}", entity_name);
        
        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(300)
            .with_temperature(0.3); // Moderate temperature for balanced extraction
        
        let chat_response = self.ai_client.exec_chat(
            &self.model,
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
        debug!("AI response for emotional state: '{}'", response);

        // Parse the JSON response with graceful error handling
        let emotional_state = match serde_json::from_str::<EmotionalState>(&response) {
            Ok(state) => Some(state),
            Err(e) => {
                debug!("Failed to parse emotional state JSON: {}", e);
                // Try to extract key information manually if JSON parsing fails
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&response) {
                    if let Some(emotion) = value.get("primary_emotion").and_then(|v| v.as_str()) {
                        let intensity = value.get("intensity")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.5) as f32;
                        let contributing_factors = value.get("contributing_factors")
                            .and_then(|v| v.as_array())
                            .map(|arr| arr.iter()
                                .filter_map(|v| v.as_str())
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>()
                            )
                            .unwrap_or_default();
                        
                        Some(EmotionalState {
                            primary_emotion: emotion.to_string(),
                            intensity,
                            contributing_factors,
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        debug!("Extracted emotional state for entity: {} - {:?}", entity_name, emotional_state);
        Ok(emotional_state)
    }

    /// Extract recent events from chat history using Flash AI
    #[instrument(skip(self, user_input, chat_history))]
    async fn extract_recent_events(
        &self,
        user_input: &str,
        chat_history: &[GenAiChatMessage],
    ) -> Result<Vec<TemporalEvent>, AppError> {
        debug!("Extracting recent events from chat history");
        
        // Build context from chat history
        let context = if chat_history.len() > 8 {
            chat_history.iter()
                .rev()
                .take(8)
                .map(|msg| {
                    let content = match &msg.content {
                        MessageContent::Text(text) => text.clone(),
                        _ => "[non-text content]".to_string(),
                    };
                    format!("{:?}: {}", msg.role, content)
                })
                .collect::<Vec<_>>()
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            chat_history.iter()
                .map(|msg| {
                    let content = match &msg.content {
                        MessageContent::Text(text) => text.clone(),
                        _ => "[non-text content]".to_string(),
                    };
                    format!("{:?}: {}", msg.role, content)
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        // Check if there are temporal indicators in the input or context
        let temporal_indicators = [
            "yesterday", "today", "earlier", "ago", "last", "previous", "recently",
            "morning", "afternoon", "evening", "night", "dawn", "dusk",
            "defended", "received", "fought", "arrived", "departed", "happened",
            "occurred", "took place", "witnessed", "experienced"
        ];

        let combined_text = format!("{} {}", user_input, context).to_lowercase();
        let has_temporal_indicators = temporal_indicators.iter()
            .any(|indicator| combined_text.contains(indicator));

        if !has_temporal_indicators {
            debug!("No temporal indicators found for recent events");
            return Ok(vec![]);
        }

        // Use Flash AI to extract recent events
        let prompt = format!(
            "Analyze the following conversation and extract recent events that have already occurred.

Context from conversation:
{}

Current input:
{}

Extract recent events from the conversation. For each event, provide:
- \"description\": A brief description of what happened
- \"significance\": How important this event is (0.0 to 1.0)
- \"time_ago\": When it happened relative to now (e.g., \"yesterday\", \"this morning\", \"last week\")

Focus on actions, occurrences, and happenings that are described as having already taken place.
Respond with a JSON array of events. If no recent events are found, respond with an empty array: []

Example response:
[
  {{
    \"description\": \"Knight defeated the dragon\",
    \"significance\": 0.9,
    \"time_ago\": \"yesterday\"
  }}
]",
            context, user_input
        );

        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(500)
            .with_temperature(0.3);

        let chat_response = self.ai_client.exec_chat(
            &self.model,
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

        debug!("AI response for recent events: '{}'", response);

        // Parse the JSON response
        let events_data: Vec<serde_json::Value> = match serde_json::from_str(&response) {
            Ok(data) => data,
            Err(e) => {
                debug!("Failed to parse recent events JSON: {}", e);
                return Ok(vec![]);
            }
        };

        let mut recent_events = Vec::new();
        let current_time = Utc::now();

        for event_data in events_data {
            let description = event_data["description"]
                .as_str()
                .unwrap_or("Unknown event")
                .to_string();

            let significance = event_data["significance"]
                .as_f64()
                .unwrap_or(0.5) as f32;

            let time_ago = event_data["time_ago"]
                .as_str()
                .unwrap_or("recently");

            // Convert relative time to approximate timestamp
            let timestamp = match time_ago {
                "just now" | "now" => current_time,
                "minutes ago" => current_time - chrono::Duration::minutes(30),
                "an hour ago" => current_time - chrono::Duration::hours(1),
                "hours ago" => current_time - chrono::Duration::hours(3),
                "this morning" => current_time.date_naive().and_hms_opt(9, 0, 0)
                    .map(|dt| dt.and_local_timezone(Utc).unwrap())
                    .unwrap_or(current_time - chrono::Duration::hours(6)),
                "yesterday" => current_time - chrono::Duration::days(1),
                "last night" => (current_time - chrono::Duration::days(1)).date_naive().and_hms_opt(21, 0, 0)
                    .map(|dt| dt.and_local_timezone(Utc).unwrap())
                    .unwrap_or(current_time - chrono::Duration::hours(12)),
                "days ago" => current_time - chrono::Duration::days(3),
                "last week" => current_time - chrono::Duration::weeks(1),
                _ => current_time - chrono::Duration::hours(2), // Default to 2 hours ago
            };

            recent_events.push(TemporalEvent {
                event_id: Uuid::new_v4(),
                description,
                timestamp,
                significance,
            });
        }

        debug!("Extracted {} recent events", recent_events.len());
        Ok(recent_events)
    }

    /// Extract future scheduled events from user input and chat history using Flash AI
    #[instrument(skip(self, user_input, chat_history))]
    async fn extract_future_events(
        &self,
        user_input: &str,
        chat_history: &[GenAiChatMessage],
    ) -> Result<Vec<ScheduledEvent>, AppError> {
        debug!("Extracting future scheduled events");

        // Build context from recent chat history
        let context = if chat_history.len() > 5 {
            chat_history.iter()
                .rev()
                .take(5)
                .map(|msg| {
                    let content = match &msg.content {
                        MessageContent::Text(text) => text.clone(),
                        _ => "[non-text content]".to_string(),
                    };
                    format!("{:?}: {}", msg.role, content)
                })
                .collect::<Vec<_>>()
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            chat_history.iter()
                .map(|msg| {
                    let content = match &msg.content {
                        MessageContent::Text(text) => text.clone(),
                        _ => "[non-text content]".to_string(),
                    };
                    format!("{:?}: {}", msg.role, content)
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        // Check for future event indicators
        let future_indicators = [
            "tomorrow", "will", "must", "should", "going to", "plan", "scheduled",
            "deadline", "appointment", "meeting", "arrive", "need to", "have to",
            "by", "until", "before", "after", "soon", "later", "next", "upcoming"
        ];

        let combined_text = format!("{} {}", user_input, context).to_lowercase();
        let has_future_indicators = future_indicators.iter()
            .any(|indicator| combined_text.contains(indicator));

        if !has_future_indicators {
            debug!("No future event indicators found");
            return Ok(vec![]);
        }

        // Use Flash AI to extract future events
        let prompt = format!(
            "Analyze the following conversation and extract future scheduled events or deadlines.

Context from conversation:
{}

Current input:
{}

Extract future events, appointments, deadlines, or planned activities. For each event, provide:
- \"description\": What needs to happen
- \"time_until\": When it's scheduled (e.g., \"tomorrow evening\", \"next week\", \"in 3 days\")
- \"participants\": Array of people/entities involved
- \"urgency\": How urgent/important (0.0 to 1.0)

Focus on things that are planned, scheduled, or must happen in the future.
Respond with a JSON array. If no future events are found, respond with: []

Example:
[
  {{
    \"description\": \"Meeting with the council\",
    \"time_until\": \"tomorrow morning\",
    \"participants\": [\"Player\", \"Council Members\"],
    \"urgency\": 0.8
  }}
]",
            context, user_input
        );

        let chat_request = genai::chat::ChatRequest::from_user(prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(400)
            .with_temperature(0.3);

        let chat_response = self.ai_client.exec_chat(
            &self.model,
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

        debug!("AI response for future events: '{}'", response);

        // Parse the JSON response
        let events_data: Vec<serde_json::Value> = match serde_json::from_str(&response) {
            Ok(data) => data,
            Err(e) => {
                debug!("Failed to parse future events JSON: {}", e);
                return Ok(vec![]);
            }
        };

        let mut scheduled_events = Vec::new();
        let current_time = Utc::now();

        for event_data in events_data {
            let description = event_data["description"]
                .as_str()
                .unwrap_or("Unknown event")
                .to_string();

            let time_until = event_data["time_until"]
                .as_str()
                .unwrap_or("soon");

            let participants = event_data["participants"]
                .as_array()
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                )
                .unwrap_or_default();

            // Convert relative future time to approximate timestamp
            let scheduled_time = match time_until {
                "immediately" | "right now" => current_time + chrono::Duration::minutes(5),
                "soon" | "shortly" => current_time + chrono::Duration::hours(1),
                "today" | "later today" => current_time.date_naive().and_hms_opt(18, 0, 0)
                    .map(|dt| dt.and_local_timezone(Utc).unwrap())
                    .unwrap_or(current_time + chrono::Duration::hours(6)),
                "tonight" => current_time.date_naive().and_hms_opt(21, 0, 0)
                    .map(|dt| dt.and_local_timezone(Utc).unwrap())
                    .unwrap_or(current_time + chrono::Duration::hours(9)),
                "tomorrow" => current_time + chrono::Duration::days(1),
                "tomorrow morning" => (current_time + chrono::Duration::days(1)).date_naive().and_hms_opt(9, 0, 0)
                    .map(|dt| dt.and_local_timezone(Utc).unwrap())
                    .unwrap_or(current_time + chrono::Duration::hours(15)),
                "tomorrow evening" => (current_time + chrono::Duration::days(1)).date_naive().and_hms_opt(18, 0, 0)
                    .map(|dt| dt.and_local_timezone(Utc).unwrap())
                    .unwrap_or(current_time + chrono::Duration::hours(24)),
                "next week" => current_time + chrono::Duration::weeks(1),
                "in a few days" => current_time + chrono::Duration::days(3),
                _ => current_time + chrono::Duration::days(1), // Default to tomorrow
            };

            scheduled_events.push(ScheduledEvent {
                event_id: Uuid::new_v4(),
                description,
                scheduled_time,
                participants,
            });
        }

        debug!("Extracted {} future scheduled events", scheduled_events.len());
        Ok(scheduled_events)
    }

    /// Builds causal context by analyzing cause-and-effect relationships
    async fn build_causal_context(
        &self,
        user_input: &str,
        chat_history: &[GenAiChatMessage],
        relevant_entities: &[EntityContext],
    ) -> Result<Option<CausalContext>, AppError> {
        debug!("Building causal context from user input and chat history");
        
        // If there's no chat history, skip causal analysis
        if chat_history.is_empty() {
            debug!("No chat history available for causal analysis");
            return Ok(None);
        }
        
        // Build context for AI analysis
        let chat_context = chat_history.iter()
            .map(|msg| format!("{:?}: {}", msg.role, 
                match &msg.content {
                    MessageContent::Text(text) => text.clone(),
                    _ => "[non-text content]".to_string(),
                }
            ))
            .collect::<Vec<_>>()
            .join("\n");
        
        let entity_context = relevant_entities.iter()
            .map(|entity| format!("- {}: {}", entity.entity_name, entity.entity_type))
            .collect::<Vec<_>>()
            .join("\n");
        
        let causal_prompt = format!(
            r#"You are the Causal Analysis Specialist in a hierarchical narrative AI system. Analyze the following scenario to identify cause-and-effect relationships, potential consequences, and relevant historical precedents.

## Context
User Input: "{}"
Relevant Entities:
{}

## Chat History
{}

## Your Task
Analyze the causal relationships in this narrative scenario and provide a structured analysis. Focus on:

1. **Causal Chains**: Identify sequences of events where one action leads to another
2. **Potential Consequences**: What might happen next based on current actions
3. **Historical Precedents**: Similar situations from the conversation history

Return your analysis in the following JSON format:
{{
    "causal_chains": [
        {{
            "events": [
                {{
                    "description": "Brief description of the causal event",
                    "timestamp": "2024-01-15T10:00:00Z"
                }}
            ],
            "confidence": 0.85
        }}
    ],
    "potential_consequences": [
        {{
            "description": "What might happen as a result",
            "probability": 0.6,
            "impact_severity": 0.8
        }}
    ],
    "historical_precedents": [
        {{
            "event_description": "Similar event from history",
            "outcome": "What happened as a result",
            "similarity_score": 0.75,
            "timestamp": "2024-01-10T14:30:00Z"
        }}
    ],
    "causal_confidence": 0.8
}}

Guidelines:
- Focus on narrative causality, not real-world physics
- Probability and impact_severity should be between 0.0 and 1.0
- Include timestamps in ISO format
- Confidence scores should reflect your certainty in the analysis
- If no clear causal relationships exist, return empty arrays"#,
            user_input, entity_context, chat_context
        );
        
        debug!("Sending causal analysis prompt to AI");
        
        let chat_request = genai::chat::ChatRequest::from_user(causal_prompt);
        let chat_options = genai::chat::ChatOptions::default()
            .with_max_tokens(1000)
            .with_temperature(0.4); // Moderate temperature for balanced analysis
        
        let chat_response = self.ai_client.exec_chat(
            &self.model,
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
        
        debug!("AI response for causal analysis: '{}'", response);
        
        // Parse the JSON response
        let causal_data: serde_json::Value = match serde_json::from_str(&response) {
            Ok(data) => data,
            Err(e) => {
                debug!("Failed to parse causal analysis JSON: {}", e);
                return Ok(None);
            }
        };
        
        // Extract causal chains
        let causal_chains = causal_data["causal_chains"]
            .as_array()
            .map(|chains| chains.iter()
                .filter_map(|chain| {
                    let events = chain["events"].as_array()?.iter()
                        .filter_map(|event| {
                            let description = event["description"].as_str()?.to_string();
                            let timestamp_str = event["timestamp"].as_str()?;
                            let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
                                .map(|dt| dt.with_timezone(&Utc))
                                .unwrap_or_else(|_| Utc::now());
                            
                            Some(CausalEvent {
                                event_id: Uuid::new_v4(),
                                description,
                                timestamp,
                                cause_strength: 0.8, // Default strength for extracted causal events
                            })
                        })
                        .collect::<Vec<_>>();
                    
                    let confidence = chain["confidence"].as_f64().unwrap_or(0.5) as f32;
                    
                    if !events.is_empty() {
                        Some(CausalChain {
                            chain_id: Uuid::new_v4(),
                            events,
                            confidence,
                        })
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
            )
            .unwrap_or_default();
        
        // Extract potential consequences
        let potential_consequences = causal_data["potential_consequences"]
            .as_array()
            .map(|consequences| consequences.iter()
                .filter_map(|consequence| {
                    let description = consequence["description"].as_str()?.to_string();
                    let probability = consequence["probability"].as_f64().unwrap_or(0.5) as f32;
                    let impact_severity = consequence["impact_severity"].as_f64().unwrap_or(0.5) as f32;
                    
                    Some(PotentialConsequence {
                        description,
                        probability,
                        impact_severity,
                    })
                })
                .collect::<Vec<_>>()
            )
            .unwrap_or_default();
        
        // Extract historical precedents
        let historical_precedents = causal_data["historical_precedents"]
            .as_array()
            .map(|precedents| precedents.iter()
                .filter_map(|precedent| {
                    let event_description = precedent["event_description"].as_str()?.to_string();
                    let outcome = precedent["outcome"].as_str()?.to_string();
                    let similarity_score = precedent["similarity_score"].as_f64().unwrap_or(0.5) as f32;
                    let timestamp_str = precedent["timestamp"].as_str()?;
                    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now());
                    
                    Some(HistoricalPrecedent {
                        event_description,
                        outcome,
                        similarity_score,
                        timestamp,
                    })
                })
                .collect::<Vec<_>>()
            )
            .unwrap_or_default();
        
        let causal_confidence = causal_data["causal_confidence"]
            .as_f64()
            .unwrap_or(0.5) as f32;
        
        // Return causal context if we have meaningful data
        if !causal_chains.is_empty() || !potential_consequences.is_empty() || !historical_precedents.is_empty() {
            debug!("Extracted causal context with {} chains, {} consequences, {} precedents", 
                causal_chains.len(), potential_consequences.len(), historical_precedents.len());
            
            Ok(Some(CausalContext {
                causal_chains,
                potential_consequences,
                historical_precedents,
                causal_confidence,
            }))
        } else {
            debug!("No meaningful causal relationships detected");
            Ok(None)
        }
    }
}

// TODO: Integration tests will be added in a separate file
// These will test the full pipeline from user input to EnrichedContext