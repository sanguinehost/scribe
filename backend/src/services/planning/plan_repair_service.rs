use std::sync::Arc;
use uuid::Uuid;
use tracing::{info, debug, warn, instrument};

use crate::{
    errors::AppError,
    services::{
        EcsEntityManager,
        planning::{
            types::*,
            repair_cache_service::RepairCacheService,
            confidence_calculator::{ConfidenceCalculator, ConfidenceBreakdown},
        },
        ecs_entity_manager::EntityQueryResult,
    },
    models::{
        chats::ChatMessage,
        ecs::*,
    },
    llm::AiClient,
    config::Config,
};
use genai::chat::{ChatRequest, ChatOptions, MessageContent};

/// Service for generating repair action sequences to fix ECS inconsistencies
pub struct PlanRepairService {
    ecs_manager: Arc<EcsEntityManager>,
    flash_client: Arc<dyn AiClient + Send + Sync>,
    config: Config,
    cache_service: Option<RepairCacheService>,
    confidence_calculator: Option<ConfidenceCalculator>,
}

impl PlanRepairService {
    pub fn new(
        ecs_manager: Arc<EcsEntityManager>,
        flash_client: Arc<dyn AiClient + Send + Sync>,
        config: Config,
    ) -> Self {
        Self {
            ecs_manager,
            flash_client,
            config,
            cache_service: None,
            confidence_calculator: None,
        }
    }

    pub fn with_cache(
        ecs_manager: Arc<EcsEntityManager>,
        flash_client: Arc<dyn AiClient + Send + Sync>,
        config: Config,
        cache_service: RepairCacheService,
    ) -> Self {
        Self {
            ecs_manager,
            flash_client,
            config,
            cache_service: Some(cache_service),
            confidence_calculator: None,
        }
    }

    pub fn with_confidence_scoring(
        ecs_manager: Arc<EcsEntityManager>,
        flash_client: Arc<dyn AiClient + Send + Sync>,
        config: Config,
        confidence_calculator: ConfidenceCalculator,
    ) -> Self {
        Self {
            ecs_manager,
            flash_client,
            config,
            cache_service: None,
            confidence_calculator: Some(confidence_calculator),
        }
    }

    pub fn with_cache_and_confidence(
        ecs_manager: Arc<EcsEntityManager>,
        flash_client: Arc<dyn AiClient + Send + Sync>,
        config: Config,
        cache_service: RepairCacheService,
        confidence_calculator: ConfidenceCalculator,
    ) -> Self {
        Self {
            ecs_manager,
            flash_client,
            config,
            cache_service: Some(cache_service),
            confidence_calculator: Some(confidence_calculator),
        }
    }

    /// Generate repair plan to fix ECS inconsistency
    #[instrument(skip(self, analysis))]
    pub async fn generate_repair_plan(
        &self,
        analysis: &InconsistencyAnalysis,
        original_plan: &Plan,
        user_id: Uuid,
    ) -> Result<Plan, AppError> {
        info!("Generating repair plan for {:?} inconsistency", analysis.inconsistency_type);

        // Check cache first if caching is enabled
        if let Some(cache_service) = &self.cache_service {
            // Check for recent failures to avoid repeated attempts
            if let Ok(Some(failure)) = cache_service.is_repair_recently_failed(user_id, analysis, original_plan).await {
                warn!("Repair recently failed for this combination, skipping: {}", failure.error_message);
                return Err(AppError::InternalServerErrorGeneric(
                    format!("Repair recently failed: {}. Retry after: {}", failure.error_message, failure.retry_after)
                ));
            }

            // Check for cached repair plan
            if let Ok(Some(cached_repair)) = cache_service.get_cached_repair_plan(user_id, original_plan, analysis).await {
                info!("Using cached repair plan from: {}", cached_repair.cached_at);
                return Ok(cached_repair.plan);
            }
        }

        // Generate the repair plan
        let repair_result = match analysis.inconsistency_type {
            InconsistencyType::MissingMovement => {
                self.generate_movement_repair(analysis, original_plan, user_id).await
            }
            InconsistencyType::MissingComponent => {
                self.generate_component_repair(analysis, original_plan, user_id).await
            }
            InconsistencyType::MissingRelationship => {
                self.generate_relationship_repair(analysis, original_plan, user_id).await
            }
            InconsistencyType::OutdatedState => {
                self.generate_general_state_repair(analysis, original_plan, user_id).await
            }
            InconsistencyType::TemporalMismatch => {
                self.generate_temporal_repair(analysis, original_plan, user_id).await
            }
        };

        // Cache the result if caching is enabled
        if let Some(cache_service) = &self.cache_service {
            match &repair_result {
                Ok(repair_plan) => {
                    // Cache successful repair plan
                    if let Err(cache_error) = cache_service.cache_repair_plan(user_id, repair_plan, original_plan, analysis).await {
                        warn!("Failed to cache repair plan: {}", cache_error);
                    }
                },
                Err(error) => {
                    // Cache failure to avoid repeated attempts
                    if let Err(cache_error) = cache_service.cache_repair_failure(user_id, analysis, original_plan, error).await {
                        warn!("Failed to cache repair failure: {}", cache_error);
                    }
                }
            }
        }

        repair_result
    }

    /// Generate repair plan with comprehensive confidence scoring
    #[instrument(skip(self, analysis))]
    pub async fn generate_repair_plan_with_confidence(
        &self,
        analysis: &InconsistencyAnalysis,
        original_plan: &Plan,
        user_id: Uuid,
    ) -> Result<(Plan, ConfidenceBreakdown), AppError> {
        info!("Generating repair plan with confidence scoring for {:?} inconsistency", analysis.inconsistency_type);

        // First generate the repair plan using existing logic
        let repair_plan = self.generate_repair_plan(analysis, original_plan, user_id).await?;

        // Calculate comprehensive confidence if calculator is available
        let confidence_breakdown = if let Some(confidence_calculator) = &self.confidence_calculator {
            confidence_calculator.calculate_repair_confidence(
                analysis,
                &repair_plan,
                original_plan,
                user_id,
            ).await?
        } else {
            // Fallback to basic confidence from analysis
            warn!("No confidence calculator available, using basic confidence from analysis");
            ConfidenceBreakdown {
                final_confidence: analysis.confidence_score,
                consistency_score: analysis.confidence_score,
                complexity_score: 0.8, // Default assumption
                relationship_score: 0.8, // Default assumption
                temporal_score: 0.9, // Default assumption
                plan_quality_score: repair_plan.metadata.confidence,
                weights: Default::default(),
                entities_analyzed: 0,
                relationships_analyzed: 0,
                max_relationship_depth: 0,
                state_age_seconds: 0,
                plan_action_count: repair_plan.actions.len() as u32,
                warnings: vec!["No confidence calculator configured".to_string()],
            }
        };

        info!("Repair plan generated with final confidence: {:.3}", confidence_breakdown.final_confidence);
        
        // Log warnings if confidence is low
        if confidence_breakdown.final_confidence < 0.5 {
            warn!("Low confidence repair plan generated ({}). Warnings: {:?}", 
                  confidence_breakdown.final_confidence, confidence_breakdown.warnings);
        }

        Ok((repair_plan, confidence_breakdown))
    }

    /// Combine repair plan with original plan
    pub fn combine_plans(&self, repair_plan: &Plan, original_plan: &Plan) -> Plan {
        let mut combined_actions = repair_plan.actions.clone();
        
        // Update dependencies in original plan to depend on repair actions
        let repair_action_ids: Vec<String> = repair_plan.actions.iter()
            .map(|a| a.id.clone())
            .collect();

        for original_action in &original_plan.actions {
            let mut updated_action = original_action.clone();
            
            // Add dependency on the last repair action
            if let Some(last_repair_id) = repair_action_ids.last() {
                if !updated_action.dependencies.contains(last_repair_id) {
                    updated_action.dependencies.push(last_repair_id.clone());
                }
            }
            
            combined_actions.push(updated_action);
        }

        Plan {
            goal: format!("Repair ECS inconsistency then: {}", original_plan.goal),
            actions: combined_actions,
            metadata: PlanMetadata {
                estimated_duration: repair_plan.metadata.estimated_duration
                    .zip(original_plan.metadata.estimated_duration)
                    .map(|(r, o)| r + o)
                    .or(original_plan.metadata.estimated_duration)
                    .or(repair_plan.metadata.estimated_duration),
                confidence: (repair_plan.metadata.confidence + original_plan.metadata.confidence) / 2.0,
                alternative_considered: Some(format!(
                    "Combined repair and original plan. Original alternative: {:?}",
                    original_plan.metadata.alternative_considered
                )),
            },
        }
    }

    /// Generate repair for missing entity movement
    async fn generate_movement_repair(
        &self,
        analysis: &InconsistencyAnalysis,
        original_plan: &Plan,
        user_id: Uuid,
    ) -> Result<Plan, AppError> {
        debug!("Generating movement repair");

        // Extract movement information from original plan
        let movement_info = self.extract_movement_info_from_plan(original_plan)?;
        
        if let Some((entity_id, expected_location)) = movement_info {
            // Verify entity exists and get current location
            if let Some(current_entity) = self.ecs_manager.get_entity(user_id, entity_id).await? {
                let current_location = self.get_entity_location(&current_entity)?;
                
                debug!("Entity {} currently at {:?}, expected at {}", 
                       entity_id, current_location, expected_location);

                let repair_action = PlannedAction {
                    id: "repair_movement".to_string(),
                    name: ActionName::MoveEntity,
                    parameters: serde_json::json!({
                        "entity_id": entity_id.to_string(),
                        "destination_id": expected_location.to_string(),
                    }),
                    preconditions: Preconditions {
                        entity_exists: Some(vec![
                            EntityExistenceCheck {
                                entity_id: Some(entity_id.to_string()),
                                entity_name: None,
                            },
                            EntityExistenceCheck {
                                entity_id: Some(expected_location.to_string()),
                                entity_name: None,
                            },
                        ]),
                        ..Default::default()
                    },
                    effects: Effects {
                        entity_moved: Some(EntityMovedEffect {
                            entity_id: entity_id.to_string(),
                            new_location: expected_location.to_string(),
                        }),
                        ..Default::default()
                    },
                    dependencies: vec![],
                };

                return Ok(Plan {
                    goal: format!("Repair missing movement for entity {}", entity_id),
                    actions: vec![repair_action],
                    metadata: PlanMetadata {
                        estimated_duration: Some(30),
                        confidence: 0.8,
                        alternative_considered: Some("Auto-generated movement repair".to_string()),
                    },
                });
            }
        }

        // Fallback: use Flash to generate movement repair
        self.generate_flash_powered_repair(analysis, "movement", user_id).await
    }

    /// Generate repair for missing components
    async fn generate_component_repair(
        &self,
        analysis: &InconsistencyAnalysis,
        original_plan: &Plan,
        user_id: Uuid,
    ) -> Result<Plan, AppError> {
        debug!("Generating component repair");

        // Extract component information from original plan
        let component_info = self.extract_component_info_from_plan(original_plan)?;
        
        if let Some((entity_id, component_type)) = component_info {
            let repair_action = PlannedAction {
                id: "repair_component".to_string(),
                name: ActionName::UpdateEntity,
                parameters: serde_json::json!({
                    "entity_id": entity_id.to_string(),
                    "component_operations": [{
                        "operation": "add",
                        "component_type": component_type,
                        "component_data": self.get_default_component_data(&component_type)
                    }]
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some(entity_id.to_string()),
                            entity_name: None,
                        },
                    ]),
                    ..Default::default()
                },
                effects: Effects {
                    component_updated: Some(vec![
                        ComponentUpdateEffect {
                            entity_id: entity_id.to_string(),
                            component_type: component_type.clone(),
                            operation: ComponentOperation::Add,
                        },
                    ]),
                    ..Default::default()
                },
                dependencies: vec![],
            };

            return Ok(Plan {
                goal: format!("Repair missing {} component for entity {}", component_type, entity_id),
                actions: vec![repair_action],
                metadata: PlanMetadata {
                    estimated_duration: Some(15),
                    confidence: 0.7,
                    alternative_considered: Some("Auto-generated component repair".to_string()),
                },
            });
        }

        // Fallback: use Flash to generate component repair
        self.generate_flash_powered_repair(analysis, "component", user_id).await
    }

    /// Generate repair for missing relationships
    async fn generate_relationship_repair(
        &self,
        analysis: &InconsistencyAnalysis,
        original_plan: &Plan,
        user_id: Uuid,
    ) -> Result<Plan, AppError> {
        debug!("Generating relationship repair");

        // Extract relationship information from original plan
        let relationship_info = self.extract_relationship_info_from_plan(original_plan)?;
        
        if let Some((source_entity, target_entity)) = relationship_info {
            let repair_action = PlannedAction {
                id: "repair_relationship".to_string(),
                name: ActionName::UpdateRelationship,
                parameters: serde_json::json!({
                    "source_entity_id": source_entity.to_string(),
                    "target_entity_id": target_entity.to_string(),
                    "trust": 0.5, // Default neutral relationship
                    "affection": 0.0,
                    "relationship_type": "acquaintance",
                }),
                preconditions: Preconditions {
                    entity_exists: Some(vec![
                        EntityExistenceCheck {
                            entity_id: Some(source_entity.to_string()),
                            entity_name: None,
                        },
                        EntityExistenceCheck {
                            entity_id: Some(target_entity.to_string()),
                            entity_name: None,
                        },
                    ]),
                    ..Default::default()
                },
                effects: Effects {
                    relationship_changed: Some(RelationshipChangeEffect {
                        source_entity: source_entity.to_string(),
                        target_entity: target_entity.to_string(),
                        trust_change: Some(0.5),
                        affection_change: Some(0.0),
                    }),
                    ..Default::default()
                },
                dependencies: vec![],
            };

            return Ok(Plan {
                goal: format!("Repair missing relationship between {} and {}", source_entity, target_entity),
                actions: vec![repair_action],
                metadata: PlanMetadata {
                    estimated_duration: Some(20),
                    confidence: 0.6,
                    alternative_considered: Some("Auto-generated relationship repair".to_string()),
                },
            });
        }

        // Fallback: use Flash to generate relationship repair
        self.generate_flash_powered_repair(analysis, "relationship", user_id).await
    }

    /// Generate repair for general outdated state
    async fn generate_general_state_repair(
        &self,
        analysis: &InconsistencyAnalysis,
        _original_plan: &Plan,
        user_id: Uuid,
    ) -> Result<Plan, AppError> {
        debug!("Generating general state repair");
        self.generate_flash_powered_repair(analysis, "general", user_id).await
    }

    /// Generate repair for temporal mismatches
    async fn generate_temporal_repair(
        &self,
        analysis: &InconsistencyAnalysis,
        _original_plan: &Plan,
        user_id: Uuid,
    ) -> Result<Plan, AppError> {
        debug!("Generating temporal repair");
        // For now, treat temporal mismatches as general state issues
        self.generate_flash_powered_repair(analysis, "temporal", user_id).await
    }

    /// Use Flash to generate repair plan
    async fn generate_flash_powered_repair(
        &self,
        analysis: &InconsistencyAnalysis,
        repair_type: &str,
        user_id: Uuid,
    ) -> Result<Plan, AppError> {
        debug!("Using Flash to generate {} repair", repair_type);

        let repair_prompt = format!(r#"
You are a Plan Repair Generator. Generate a minimal repair plan to fix the identified ECS inconsistency.

INCONSISTENCY TYPE: {:?}
REPAIR REASONING: {}
ECS STATE SUMMARY: {}
NARRATIVE EVIDENCE: {}

TASK: Generate a minimal JSON plan with 1-3 actions to repair this inconsistency.

AVAILABLE ACTIONS:
- find_entity: Find entities by criteria
- create_entity: Create new entities  
- update_entity: Add/update/remove components
- move_entity: Move entity to new parent
- update_relationship: Create/update relationships
- add_item_to_inventory: Add items to inventory

RESPONSE FORMAT (JSON):
{{
  "goal": "Brief description of repair",
  "actions": [
    {{
      "id": "repair_action_1",
      "name": "action_name",
      "parameters": {{}},
      "preconditions": {{}},
      "effects": {{}},
      "dependencies": []
    }}
  ],
  "metadata": {{
    "estimated_duration": 30,
    "confidence": 0.7,
    "alternative_considered": null
  }}
}}

Guidelines:
- Generate MINIMAL repairs (1-3 actions max)
- Use conservative parameter values
- Include proper preconditions
- Don't make assumptions about entity IDs
- Focus on fixing the specific inconsistency
- Make repairs that are likely to be valid

Generate the repair plan:
"#, 
            analysis.inconsistency_type,
            self.sanitize_text(&analysis.repair_reasoning),
            self.sanitize_text(&analysis.ecs_state_summary),
            analysis.narrative_evidence.join("; ")
        );

        let chat_request = ChatRequest::from_user(repair_prompt);

        let chat_options = ChatOptions {
            temperature: Some(0.4), // Slightly higher for creative but controlled repair generation
            max_tokens: Some(800),
            ..Default::default()
        };

        let response = self.flash_client.exec_chat(
            &self.config.agentic_extraction_model,
            chat_request,
            Some(chat_options),
        ).await
        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Flash repair generation failed: {}", e)))?;

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
        
        // Parse Flash response into Plan
        match serde_json::from_str::<Plan>(&response_text) {
            Ok(mut plan) => {
                // Validate and sanitize the generated plan
                plan.goal = self.sanitize_text(&plan.goal);
                
                // Ensure action IDs are unique and safe
                for (i, action) in plan.actions.iter_mut().enumerate() {
                    action.id = format!("flash_repair_{}", i + 1);
                }
                
                info!("Flash generated repair plan with {} actions", plan.actions.len());
                Ok(plan)
            }
            Err(e) => {
                warn!("Failed to parse Flash repair plan: {}", e);
                debug!("Flash response was: {}", response_text);
                
                // Fallback: create a minimal no-op repair plan
                Ok(Plan {
                    goal: "Minimal repair plan (Flash generation failed)".to_string(),
                    actions: vec![
                        PlannedAction {
                            id: "fallback_repair".to_string(),
                            name: ActionName::FindEntity,
                            parameters: serde_json::json!({
                                "criteria": {
                                    "type": "ByName",
                                    "name": "RepairEntity"
                                }
                            }),
                            preconditions: Preconditions::default(),
                            effects: Effects::default(),
                            dependencies: vec![],
                        }
                    ],
                    metadata: PlanMetadata {
                        estimated_duration: Some(10),
                        confidence: 0.3,
                        alternative_considered: Some("Fallback repair due to Flash parsing failure".to_string()),
                    },
                })
            }
        }
    }

    /// Extract movement information from plan
    fn extract_movement_info_from_plan(&self, plan: &Plan) -> Result<Option<(Uuid, Uuid)>, AppError> {
        for action in &plan.actions {
            if let Some(location_checks) = &action.preconditions.entity_at_location {
                for check in location_checks {
                    if let (Ok(entity_id), Ok(location_id)) = (
                        Uuid::parse_str(&check.entity_id),
                        Uuid::parse_str(&check.location_id)
                    ) {
                        return Ok(Some((entity_id, location_id)));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Extract component information from plan
    fn extract_component_info_from_plan(&self, plan: &Plan) -> Result<Option<(Uuid, String)>, AppError> {
        for action in &plan.actions {
            if let Some(component_checks) = &action.preconditions.entity_has_component {
                for check in component_checks {
                    if let Ok(entity_id) = Uuid::parse_str(&check.entity_id) {
                        return Ok(Some((entity_id, check.component_type.clone())));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Extract relationship information from plan
    fn extract_relationship_info_from_plan(&self, plan: &Plan) -> Result<Option<(Uuid, Uuid)>, AppError> {
        for action in &plan.actions {
            if let Some(relationship_checks) = &action.preconditions.relationship_exists {
                for check in relationship_checks {
                    if let (Ok(source_id), Ok(target_id)) = (
                        Uuid::parse_str(&check.source_entity),
                        Uuid::parse_str(&check.target_entity)
                    ) {
                        return Ok(Some((source_id, target_id)));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Get entity's current location
    fn get_entity_location(&self, entity_result: &EntityQueryResult) -> Result<Option<Uuid>, AppError> {
        if let Some(parent_link) = entity_result.components.iter()
            .find(|c| c.component_type == "ParentLink") {
            let parent_data: ParentLinkComponent = serde_json::from_value(parent_link.component_data.clone())
                .map_err(|e| AppError::InternalServerErrorGeneric(format!("Failed to parse ParentLink: {}", e)))?;
            Ok(Some(parent_data.parent_entity_id))
        } else {
            Ok(None)
        }
    }

    /// Get default component data for a component type
    fn get_default_component_data(&self, component_type: &str) -> serde_json::Value {
        match component_type {
            "Reputation" => serde_json::json!({
                "pilot_skill": 0.5,
                "combat_skill": 0.5,
                "social_skill": 0.5,
                "total_reputation": 0.5
            }),
            "Health" => serde_json::json!({
                "current_health": 100,
                "max_health": 100,
                "status_effects": []
            }),
            "Skills" => serde_json::json!({
                "skills": {},
                "experience": 0
            }),
            "Mood" => serde_json::json!({
                "current_mood": "neutral",
                "mood_factors": []
            }),
            _ => serde_json::json!({
                "created_by_repair": true,
                "default_values": true
            })
        }
    }

    /// Sanitize text to prevent injection attacks
    fn sanitize_text(&self, text: &str) -> String {
        text.chars()
            .filter(|c| c.is_alphanumeric() || c.is_whitespace() || ".,!?-_()[]{}:;'\"".contains(*c))
            .take(500) // Limit length
            .collect()
    }
}