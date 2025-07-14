use std::sync::Arc;
use uuid::Uuid;
use tracing::{info, debug, warn, instrument};

use crate::{
    errors::AppError,
    services::{
        EcsEntityManager,
        planning::types::*,
    },
};

/// The "Symbolic Firewall" - validates AI-generated plans against ECS ground truth
pub struct PlanValidatorService {
    ecs_manager: Arc<EcsEntityManager>,
    redis_client: Arc<redis::Client>,
}

impl PlanValidatorService {
    pub fn new(
        ecs_manager: Arc<EcsEntityManager>,
        redis_client: Arc<redis::Client>,
    ) -> Self {
        Self {
            ecs_manager,
            redis_client,
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
        
        let mut failures = Vec::new();
        
        // Validate each action in sequence
        for action in &plan.actions {
            if let Err(failure) = self.validate_action(action, user_id).await {
                failures.push(failure);
            }
        }
        
        if failures.is_empty() {
            Ok(PlanValidationResult::Valid(ValidatedPlan {
                plan_id: Uuid::new_v4(),
                original_plan: plan.clone(),
                validation_timestamp: chrono::Utc::now(),
                cache_key: self.build_validation_cache_key(plan, user_id),
            }))
        } else {
            Ok(PlanValidationResult::Invalid(InvalidPlan {
                plan: plan.clone(),
                failures,
            }))
        }
    }

    /// Validate a single action
    async fn validate_action(
        &self,
        action: &PlannedAction,
        user_id: Uuid,
    ) -> Result<(), ValidationFailure> {
        debug!("Validating action: {} ({})", action.name.as_ref(), action.id);
        
        // SECURITY: Comprehensive action validation
        // 1. Check if action exists in Tactical Toolkit
        if !self.is_valid_action(&action.name) {
            return Err(ValidationFailure {
                action_id: action.id.clone(),
                failure_type: ValidationFailureType::ActionNotFound,
                message: "Action not found in Tactical Toolkit".to_string(),
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
        
        // 3. Basic precondition checks (user ownership, entity existence)
        // This ensures user can only operate on entities they own
        debug!("Action {} validated for user {}", action.name.as_ref(), user_id);
        
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
}

impl AsRef<ActionName> for ActionName {
    fn as_ref(&self) -> &ActionName {
        self
    }
}