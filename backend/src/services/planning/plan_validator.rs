use std::sync::Arc;
use std::collections::{HashSet, HashMap};
use uuid::Uuid;
use tracing::{info, debug, warn, instrument};
use redis::AsyncCommands;

use crate::{
    errors::AppError,
    services::{
        EcsEntityManager,
        planning::{
            types::*,
            ecs_consistency_analyzer::EcsConsistencyAnalyzer,
            plan_repair_service::PlanRepairService,
        },
    },
    models::{
        ecs::{InventoryComponent, Relationship},
        chats::ChatMessage,
    },
    llm::AiClient,
    config::Config,
};

/// The "Symbolic Firewall" - validates AI-generated plans against ECS ground truth
pub struct PlanValidatorService {
    ecs_manager: Arc<EcsEntityManager>,
    redis_client: Arc<redis::Client>,
    consistency_analyzer: Option<EcsConsistencyAnalyzer>,
    repair_service: Option<PlanRepairService>,
}

impl PlanValidatorService {
    pub fn new(
        ecs_manager: Arc<EcsEntityManager>,
        redis_client: Arc<redis::Client>,
    ) -> Self {
        Self {
            ecs_manager,
            redis_client,
            consistency_analyzer: None,
            repair_service: None,
        }
    }

    pub fn with_repair_capability(
        ecs_manager: Arc<EcsEntityManager>,
        redis_client: Arc<redis::Client>,
        flash_client: Arc<dyn AiClient + Send + Sync>,
        config: Config,
    ) -> Self {
        let consistency_analyzer = EcsConsistencyAnalyzer::new(
            ecs_manager.clone(),
            flash_client.clone(),
            config.clone(),
        );
        
        let repair_service = PlanRepairService::new(
            ecs_manager.clone(),
            flash_client,
            config,
        );

        Self {
            ecs_manager,
            redis_client,
            consistency_analyzer: Some(consistency_analyzer),
            repair_service: Some(repair_service),
        }
    }

    /// Validate a plan against the current world state
    #[instrument(skip(self))]
    pub async fn validate_plan(
        &self,
        plan: &Plan,
        user_id: Uuid,
    ) -> Result<PlanValidationResult, AppError> {
        info!("Validating plan for goal: {}", plan.goal);
        
        // Check cache first
        let cache_key = self.build_validation_cache_key(plan, user_id);
        if let Ok(cached) = self.get_cached_validation(&cache_key).await {
            debug!("Using cached validation result for plan");
            return Ok(cached);
        }
        
        let mut failures = Vec::new();
        
        // First validate dependency graph
        if let Err(dep_failures) = self.validate_dependencies(plan) {
            failures.extend(dep_failures);
        }
        
        // Then validate each action in sequence
        for action in &plan.actions {
            // Collect all failures from this action
            match self.validate_action_comprehensive(action, user_id).await {
                Ok(_) => {},
                Err(action_failures) => {
                    failures.extend(action_failures);
                }
            }
        }
        
        let result = if failures.is_empty() {
            PlanValidationResult::Valid(ValidatedPlan {
                plan_id: Uuid::new_v4(),
                original_plan: plan.clone(),
                validation_timestamp: chrono::Utc::now(),
                cache_key: cache_key.clone(),
            })
        } else {
            PlanValidationResult::Invalid(InvalidPlan {
                plan: plan.clone(),
                failures,
            })
        };
        
        // Cache the result
        let _ = self.cache_validation_result(&cache_key, &result).await;
        
        Ok(result)
    }

    /// Enhanced validation with repair capability for ECS inconsistencies
    #[instrument(skip(self, recent_context))]
    pub async fn validate_plan_with_repair(
        &self,
        plan: &Plan,
        user_id: Uuid,
        recent_context: &[ChatMessage],
    ) -> Result<PlanValidationResult, AppError> {
        info!("Validating plan with repair capability for goal: {}", plan.goal);

        // 1. Standard validation first
        let validation_result = self.validate_plan(plan, user_id).await?;

        match validation_result {
            PlanValidationResult::Valid(valid) => {
                debug!("Plan is valid, no repair needed");
                Ok(PlanValidationResult::Valid(valid))
            }
            PlanValidationResult::Invalid(invalid) => {
                debug!("Plan failed validation, analyzing for potential repairs");

                // 2. Check if repair capability is available
                if let (Some(analyzer), Some(repair_service)) = (&self.consistency_analyzer, &self.repair_service) {
                    
                    // 3. Analyze if ECS might be inconsistent
                    match analyzer.analyze_inconsistency(plan, &invalid.failures, user_id, recent_context).await? {
                        Some(analysis) => {
                            info!("Inconsistency detected: {:?} with confidence {}", 
                                  analysis.inconsistency_type, 
                                  analysis.confidence_score);

                            // Check confidence threshold (could be configurable)
                            let confidence_score = analysis.confidence_score;
                            
                            if confidence_score > 0.7 {
                                debug!("High confidence inconsistency, generating repair plan");
                                
                                // 4. Generate repair plan
                                match repair_service.generate_repair_plan(&analysis, plan, user_id).await {
                                    Ok(repair_plan) => {
                                        // 5. Combine repair with original plan
                                        let combined_plan = repair_service.combine_plans(&repair_plan, plan);
                                        
                                        // 6. Validate combined plan
                                        let combined_validation = self.validate_plan(&combined_plan, user_id).await?;
                                        
                                        match combined_validation {
                                            PlanValidationResult::Valid(_) => {
                                                info!("Repair successful, returning repairable invalid plan");
                                                Ok(PlanValidationResult::RepairableInvalid(RepairableInvalidPlan {
                                                    original_plan: plan.clone(),
                                                    repair_actions: repair_plan.actions,
                                                    combined_plan,
                                                    inconsistency_analysis: analysis,
                                                    confidence_score,
                                                }))
                                            }
                                            _ => {
                                                warn!("Repair plan validation failed, returning original invalid result");
                                                Ok(PlanValidationResult::Invalid(invalid))
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to generate repair plan: {}", e);
                                        Ok(PlanValidationResult::Invalid(invalid))
                                    }
                                }
                            } else {
                                debug!("Low confidence inconsistency ({}), not repairing", confidence_score);
                                Ok(PlanValidationResult::Invalid(invalid))
                            }
                        }
                        None => {
                            debug!("No ECS inconsistency detected");
                            Ok(PlanValidationResult::Invalid(invalid))
                        }
                    }
                } else {
                    debug!("Repair capability not available, returning standard invalid result");
                    Ok(PlanValidationResult::Invalid(invalid))
                }
            }
            PlanValidationResult::RepairableInvalid(_) => {
                // This shouldn't happen in normal flow, but handle gracefully
                warn!("Unexpected RepairableInvalid result from standard validation");
                Ok(validation_result)
            }
        }
    }

    /// Validate a single action and return all failures (comprehensive)
    async fn validate_action_comprehensive(
        &self,
        action: &PlannedAction,
        user_id: Uuid,
    ) -> Result<(), Vec<ValidationFailure>> {
        let mut failures = Vec::new();
        
        // 1. Check if action exists in Tactical Toolkit
        if !self.is_valid_action(&action.name) {
            failures.push(ValidationFailure {
                action_id: action.id.clone(),
                failure_type: ValidationFailureType::ActionNotFound,
                message: format!("Action '{}' not found in Tactical Toolkit", action.name),
            });
        }
        
        // 2. Validate parameters exist and are well-formed
        if action.parameters.is_null() || action.parameters.as_object().map_or(true, |obj| obj.is_empty()) {
            failures.push(ValidationFailure {
                action_id: action.id.clone(),
                failure_type: ValidationFailureType::InvalidParameters,
                message: "Action requires parameters".to_string(),
            });
        }
        
        // 3. Validate parameter structure based on action type
        if let Err(param_failure) = self.validate_action_parameters(&action.name, &action.parameters) {
            failures.push(param_failure);
        }
        
        // 4. Validate all preconditions against ECS ground truth
        if let Err(precondition_failures) = self.validate_preconditions(&action.preconditions, &action.id, user_id).await {
            failures.extend(precondition_failures);
        }
        
        if failures.is_empty() {
            debug!("Action {} validated successfully", action.id);
            Ok(())
        } else {
            Err(failures)
        }
    }

    /// Validate a single action with comprehensive precondition checking (original single-failure version)
    async fn validate_action(
        &self,
        action: &PlannedAction,
        user_id: Uuid,
    ) -> Result<(), ValidationFailure> {
        debug!("Validating action: {} ({})", action.name, action.id);
        
        // 1. Check if action exists in Tactical Toolkit
        if !self.is_valid_action(&action.name) {
            return Err(ValidationFailure {
                action_id: action.id.clone(),
                failure_type: ValidationFailureType::ActionNotFound,
                message: format!("Action '{}' not found in Tactical Toolkit", action.name),
            });
        }
        
        // 2. Validate parameters exist and are well-formed
        if action.parameters.is_null() || action.parameters.as_object().map_or(true, |obj| obj.is_empty()) {
            return Err(ValidationFailure {
                action_id: action.id.clone(),
                failure_type: ValidationFailureType::InvalidParameters,
                message: "Action requires parameters".to_string(),
            });
        }
        
        // 3. Validate parameter structure based on action type
        self.validate_action_parameters(&action.name, &action.parameters)?;
        
        // 4. Validate all preconditions against ECS ground truth
        if let Err(precondition_failures) = self.validate_preconditions(&action.preconditions, &action.id, user_id).await {
            // Return the first failure for now (maintaining single-failure interface)
            // In the future, we could extend validate_action to return multiple failures
            return Err(precondition_failures.into_iter().next().unwrap());
        }
        
        debug!("Action {} validated successfully", action.id);
        Ok(())
    }

    /// Check if action exists in the Tactical Toolkit
    fn is_valid_action(&self, action_name: &ActionName) -> bool {
        // Valid action names from the Tactical Toolkit (Task 2.3 & 2.4)
        matches!(action_name, 
            ActionName::CreateEntity |
            ActionName::UpdateEntity |
            ActionName::FindEntity |
            ActionName::GetEntityDetails |
            ActionName::MoveEntity |
            ActionName::GetContainedEntities |
            ActionName::GetSpatialContext |
            ActionName::AddItemToInventory |
            ActionName::RemoveItemFromInventory |
            ActionName::UpdateRelationship
        )
    }

    /// Build cache key for validation results
    fn build_validation_cache_key(&self, plan: &Plan, user_id: Uuid) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        plan.goal.hash(&mut hasher);
        plan.actions.len().hash(&mut hasher);
        user_id.hash(&mut hasher);
        
        format!("validation:{}:{:x}", user_id, hasher.finish())
    }
    
    /// Validate action parameters match expected schema
    fn validate_action_parameters(
        &self,
        action_name: &ActionName,
        parameters: &serde_json::Value,
    ) -> Result<(), ValidationFailure> {
        let obj = parameters.as_object()
            .ok_or_else(|| ValidationFailure {
                action_id: "unknown".to_string(),
                failure_type: ValidationFailureType::InvalidParameters,
                message: "Parameters must be an object".to_string(),
            })?;
        
        // Validate required parameters for each action type
        match action_name {
            ActionName::MoveEntity => {
                if !obj.contains_key("entity_id") || !obj.contains_key("destination_id") {
                    return Err(ValidationFailure {
                        action_id: "unknown".to_string(),
                        failure_type: ValidationFailureType::InvalidParameters,
                        message: "MoveEntity requires 'entity_id' and 'destination_id'".to_string(),
                    });
                }
            }
            ActionName::AddItemToInventory | ActionName::RemoveItemFromInventory => {
                if !obj.contains_key("owner_entity_id") || !obj.contains_key("item_entity_id") || !obj.contains_key("quantity") {
                    return Err(ValidationFailure {
                        action_id: "unknown".to_string(),
                        failure_type: ValidationFailureType::InvalidParameters,
                        message: format!("{} requires 'owner_entity_id', 'item_entity_id', and 'quantity'", action_name),
                    });
                }
            }
            ActionName::UpdateRelationship => {
                if !obj.contains_key("source_entity_id") || !obj.contains_key("target_entity_id") {
                    return Err(ValidationFailure {
                        action_id: "unknown".to_string(),
                        failure_type: ValidationFailureType::InvalidParameters,
                        message: "UpdateRelationship requires 'source_entity_id' and 'target_entity_id'".to_string(),
                    });
                }
            }
            _ => {
                // Other actions have flexible parameters
            }
        }
        
        Ok(())
    }
    
    /// Validate all preconditions against ECS ground truth
    async fn validate_preconditions(
        &self,
        preconditions: &Preconditions,
        action_id: &str,
        user_id: Uuid,
    ) -> Result<(), Vec<ValidationFailure>> {
        let mut failures = Vec::new();
        
        // Check entity existence
        if let Some(entity_checks) = &preconditions.entity_exists {
            for check in entity_checks {
                if let Err(failure) = self.validate_entity_exists(check, action_id, user_id).await {
                    failures.push(failure);
                }
            }
        }
        
        // Check entity locations
        if let Some(location_checks) = &preconditions.entity_at_location {
            for check in location_checks {
                if let Err(failure) = self.validate_entity_at_location(check, action_id, user_id).await {
                    failures.push(failure);
                }
            }
        }
        
        // Check entity components
        if let Some(component_checks) = &preconditions.entity_has_component {
            for check in component_checks {
                if let Err(failure) = self.validate_entity_has_component(check, action_id, user_id).await {
                    failures.push(failure);
                }
            }
        }
        
        // Check inventory space
        if let Some(inventory_check) = &preconditions.inventory_has_space {
            if let Err(failure) = self.validate_inventory_has_space(inventory_check, action_id, user_id).await {
                failures.push(failure);
            }
        }
        
        // Check relationships
        if let Some(relationship_checks) = &preconditions.relationship_exists {
            for check in relationship_checks {
                if let Err(failure) = self.validate_relationship_exists(check, action_id, user_id).await {
                    failures.push(failure);
                }
            }
        }
        
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }
    
    /// Validate entity existence precondition
    async fn validate_entity_exists(
        &self,
        check: &EntityExistenceCheck,
        action_id: &str,
        user_id: Uuid,
    ) -> Result<(), ValidationFailure> {
        let entity_id = if let Some(id_str) = &check.entity_id {
            Uuid::parse_str(id_str).map_err(|_| ValidationFailure {
                action_id: action_id.to_string(),
                failure_type: ValidationFailureType::InvalidParameters,
                message: format!("Invalid entity ID format: {}", id_str),
            })?
        } else if let Some(_name) = &check.entity_name {
            // Entity name is provided for context but we still need entity_id
            // In a real implementation, we'd search for entities by name
            // For now, we require entity_id to be provided
            return Err(ValidationFailure {
                action_id: action_id.to_string(),
                failure_type: ValidationFailureType::InvalidParameters,
                message: "Entity validation requires entity_id".to_string(),
            });
        } else {
            return Err(ValidationFailure {
                action_id: action_id.to_string(),
                failure_type: ValidationFailureType::InvalidParameters,
                message: "Entity check requires either entity_id or entity_name".to_string(),
            });
        };
        
        // Check if entity exists and is owned by user
        debug!("Checking entity existence: entity_id={}, user_id={}", entity_id, user_id);
        match self.ecs_manager.get_entity(user_id, entity_id).await {
            Ok(Some(entity)) => {
                debug!("Entity found: {:?}", entity.entity.id);
                Ok(())
            },
            Ok(None) => {
                warn!("Entity not found: entity_id={}, user_id={}", entity_id, user_id);
                Err(ValidationFailure {
                    action_id: action_id.to_string(),
                    failure_type: ValidationFailureType::EntityNotFound,
                    message: "Entity not found or not accessible".to_string(),
                })
            },
            Err(e) => {
                warn!("Error checking entity existence: {}", e);
                Err(ValidationFailure {
                    action_id: action_id.to_string(),
                    failure_type: ValidationFailureType::EntityNotFound,
                    message: "Failed to verify entity existence".to_string(),
                })
            }
        }
    }
    
    /// Validate entity location precondition
    async fn validate_entity_at_location(
        &self,
        check: &EntityLocationCheck,
        action_id: &str,
        user_id: Uuid,
    ) -> Result<(), ValidationFailure> {
        let entity_id = Uuid::parse_str(&check.entity_id).map_err(|_| ValidationFailure {
            action_id: action_id.to_string(),
            failure_type: ValidationFailureType::InvalidParameters,
            message: "Invalid entity ID format".to_string(),
        })?;
        
        let location_id = Uuid::parse_str(&check.location_id).map_err(|_| ValidationFailure {
            action_id: action_id.to_string(),
            failure_type: ValidationFailureType::InvalidParameters,
            message: "Invalid location ID format".to_string(),
        })?;
        
        // Get entity with components to check parent
        match self.ecs_manager.get_entity(user_id, entity_id).await {
            Ok(Some(entity_result)) => {
                // Check if entity has parent link component matching the location
                let parent_link = entity_result.components.iter()
                    .find(|c| c.component_type == "ParentLink");
                
                if let Some(parent_component) = parent_link {
                    let parent_link_data: crate::models::ecs::ParentLinkComponent = 
                        serde_json::from_value(parent_component.component_data.clone())
                            .map_err(|_| ValidationFailure {
                                action_id: action_id.to_string(),
                                failure_type: ValidationFailureType::PreconditionNotMet,
                                message: "Failed to parse parent link component".to_string(),
                            })?;
                    
                    if parent_link_data.parent_entity_id != location_id {
                        return Err(ValidationFailure {
                            action_id: action_id.to_string(),
                            failure_type: ValidationFailureType::PreconditionNotMet,
                            message: format!("Entity {} is not at location {}", entity_id, location_id),
                        });
                    }
                } else {
                    // No parent link means entity is not at any location
                    return Err(ValidationFailure {
                        action_id: action_id.to_string(),
                        failure_type: ValidationFailureType::PreconditionNotMet,
                        message: "Entity has no location".to_string(),
                    });
                }
                Ok(())
            }
            Ok(None) => Err(ValidationFailure {
                action_id: action_id.to_string(),
                failure_type: ValidationFailureType::EntityNotFound,
                message: "Entity not found".to_string(),
            }),
            Err(e) => {
                warn!("Error checking entity location: {}", e);
                Err(ValidationFailure {
                    action_id: action_id.to_string(),
                    failure_type: ValidationFailureType::PreconditionNotMet,
                    message: "Failed to verify entity location".to_string(),
                })
            }
        }
    }
    
    /// Validate entity has component precondition
    async fn validate_entity_has_component(
        &self,
        check: &EntityComponentCheck,
        action_id: &str,
        user_id: Uuid,
    ) -> Result<(), ValidationFailure> {
        let entity_id = Uuid::parse_str(&check.entity_id).map_err(|_| ValidationFailure {
            action_id: action_id.to_string(),
            failure_type: ValidationFailureType::InvalidParameters,
            message: "Invalid entity ID format".to_string(),
        })?;
        
        // Get entity with components
        match self.ecs_manager.get_entity(user_id, entity_id).await {
            Ok(Some(entity_result)) => {
                // Check if entity has the required component type
                let has_component = entity_result.components.iter()
                    .any(|comp| comp.component_type == check.component_type);
                
                if has_component {
                    Ok(())
                } else {
                    Err(ValidationFailure {
                        action_id: action_id.to_string(),
                        failure_type: ValidationFailureType::PreconditionNotMet,
                        message: format!("missing component: {}", check.component_type),
                    })
                }
            }
            Ok(None) => Err(ValidationFailure {
                action_id: action_id.to_string(),
                failure_type: ValidationFailureType::EntityNotFound,
                message: "Entity not found".to_string(),
            }),
            Err(e) => {
                warn!("Error checking entity component: {}", e);
                Err(ValidationFailure {
                    action_id: action_id.to_string(),
                    failure_type: ValidationFailureType::PreconditionNotMet,
                    message: "Failed to verify entity component".to_string(),
                })
            }
        }
    }
    
    /// Validate inventory has space precondition
    async fn validate_inventory_has_space(
        &self,
        check: &InventorySpaceCheck,
        action_id: &str,
        user_id: Uuid,
    ) -> Result<(), ValidationFailure> {
        let entity_id = Uuid::parse_str(&check.entity_id).map_err(|_| ValidationFailure {
            action_id: action_id.to_string(),
            failure_type: ValidationFailureType::InvalidParameters,
            message: "Invalid entity ID format".to_string(),
        })?;
        
        // Get entity with components
        match self.ecs_manager.get_entity(user_id, entity_id).await {
            Ok(Some(entity_result)) => {
                // Find inventory component
                let inventory_component = entity_result.components.iter()
                    .find(|c| c.component_type == "Inventory")
                    .ok_or_else(|| ValidationFailure {
                        action_id: action_id.to_string(),
                        failure_type: ValidationFailureType::PreconditionNotMet,
                        message: "Entity has no inventory component".to_string(),
                    })?;
                
                // Deserialize inventory component
                let inventory: InventoryComponent = serde_json::from_value(inventory_component.component_data.clone())
                    .map_err(|_| ValidationFailure {
                        action_id: action_id.to_string(),
                        failure_type: ValidationFailureType::PreconditionNotMet,
                        message: "Failed to parse inventory component".to_string(),
                    })?;
                
                let used_slots = inventory.items.len();
                let available_slots = inventory.capacity as usize - used_slots;
                
                if available_slots < check.required_slots as usize {
                    return Err(ValidationFailure {
                        action_id: action_id.to_string(),
                        failure_type: ValidationFailureType::PreconditionNotMet,
                        message: format!(
                            "Insufficient inventory space: {} available, {} required",
                            available_slots, check.required_slots
                        ),
                    });
                }
                Ok(())
            }
            Ok(None) => Err(ValidationFailure {
                action_id: action_id.to_string(),
                failure_type: ValidationFailureType::EntityNotFound,
                message: "Entity not found".to_string(),
            }),
            Err(e) => {
                warn!("Error checking inventory space: {}", e);
                Err(ValidationFailure {
                    action_id: action_id.to_string(),
                    failure_type: ValidationFailureType::PreconditionNotMet,
                    message: "Failed to verify inventory space".to_string(),
                })
            }
        }
    }
    
    /// Validate relationship exists precondition
    async fn validate_relationship_exists(
        &self,
        check: &RelationshipCheck,
        action_id: &str,
        user_id: Uuid,
    ) -> Result<(), ValidationFailure> {
        let source_id = Uuid::parse_str(&check.source_entity).map_err(|_| ValidationFailure {
            action_id: action_id.to_string(),
            failure_type: ValidationFailureType::InvalidParameters,
            message: "Invalid source entity ID format".to_string(),
        })?;
        
        let target_id = Uuid::parse_str(&check.target_entity).map_err(|_| ValidationFailure {
            action_id: action_id.to_string(),
            failure_type: ValidationFailureType::InvalidParameters,
            message: "Invalid target entity ID format".to_string(),
        })?;
        
        // Get relationships from source entity
        match self.ecs_manager.get_relationships(user_id, source_id).await {
            Ok(relationships) => {
                let relationship = relationships.iter()
                    .find(|r| r.target_entity_id == target_id);
                
                match relationship {
                    Some(rel) => {
                        // Check minimum trust if specified
                        if let Some(min_trust) = check.min_trust {
                            if rel.trust < min_trust {
                                return Err(ValidationFailure {
                                    action_id: action_id.to_string(),
                                    failure_type: ValidationFailureType::PreconditionNotMet,
                                    message: format!(
                                        "Insufficient trust: {} < {} required",
                                        rel.trust, min_trust
                                    ),
                                });
                            }
                        }
                        Ok(())
                    }
                    None => Err(ValidationFailure {
                        action_id: action_id.to_string(),
                        failure_type: ValidationFailureType::PreconditionNotMet,
                        message: "relationship does not exist".to_string(),
                    }),
                }
            }
            Err(e) => {
                warn!("Error checking relationship: {}", e);
                Err(ValidationFailure {
                    action_id: action_id.to_string(),
                    failure_type: ValidationFailureType::PreconditionNotMet,
                    message: "Failed to verify relationship".to_string(),
                })
            }
        }
    }
    
    /// Validate plan dependencies (no circular references)
    fn validate_dependencies(&self, plan: &Plan) -> Result<(), Vec<ValidationFailure>> {
        let mut failures = Vec::new();
        let mut visited = HashSet::new();
        let mut recursion_stack = HashSet::new();
        
        // Build dependency graph
        let mut dependencies: HashMap<String, Vec<String>> = HashMap::new();
        for action in &plan.actions {
            dependencies.insert(action.id.clone(), action.dependencies.clone());
        }
        
        // Check for circular dependencies using DFS
        for action in &plan.actions {
            if !visited.contains(&action.id) {
                if let Err(cycle_action) = self.detect_cycle(
                    &action.id,
                    &dependencies,
                    &mut visited,
                    &mut recursion_stack,
                ) {
                    failures.push(ValidationFailure {
                        action_id: cycle_action,
                        failure_type: ValidationFailureType::InvalidDependency,
                        message: "Circular dependency detected".to_string(),
                    });
                }
            }
        }
        
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures)
        }
    }
    
    /// Detect cycles in dependency graph
    fn detect_cycle(
        &self,
        node: &str,
        graph: &HashMap<String, Vec<String>>,
        visited: &mut HashSet<String>,
        recursion_stack: &mut HashSet<String>,
    ) -> Result<(), String> {
        visited.insert(node.to_string());
        recursion_stack.insert(node.to_string());
        
        if let Some(neighbors) = graph.get(node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    self.detect_cycle(neighbor, graph, visited, recursion_stack)?;
                } else if recursion_stack.contains(neighbor) {
                    return Err(neighbor.clone());
                }
            }
        }
        
        recursion_stack.remove(node);
        Ok(())
    }
    
    /// Get cached validation result
    async fn get_cached_validation(&self, cache_key: &str) -> Result<PlanValidationResult, AppError> {
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Redis connection error: {}", e)))?;
        
        let cached: Option<String> = conn.get(cache_key).await
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Redis get error: {}", e)))?;
        
        match cached {
            Some(data) => serde_json::from_str(&data)
                .map_err(|e| AppError::InternalServerErrorGeneric(format!("Cache deserialization error: {}", e))),
            None => Err(AppError::NotFound("No cached validation".to_string())),
        }
    }
    
    /// Cache validation result
    async fn cache_validation_result(
        &self,
        cache_key: &str,
        result: &PlanValidationResult,
    ) -> Result<(), AppError> {
        let mut conn = self.redis_client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Redis connection error: {}", e)))?;
        
        let serialized = serde_json::to_string(result)
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Serialization error: {}", e)))?;
        
        // Cache for 3 minutes
        let _: () = conn.set_ex(cache_key, serialized, 180).await
            .map_err(|e| AppError::InternalServerErrorGeneric(format!("Redis set error: {}", e)))?;
        
        Ok(())
    }
}

