// backend/src/services/planning/virtual_ecs_state.rs
//
// Virtual ECS State Projection Layer
//
// This module provides the missing intermediary layer between plan validation and ECS state.
// It enables sequential validation of actions against projected state changes rather than
// static current state, solving the core issue where repair plans combine multiple actions
// that depend on each other's effects.

use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use tracing::{info, debug, warn, instrument};

use crate::{
    errors::AppError,
    services::{
        EcsEntityManager,
        planning::types::*,
        ecs_entity_manager::EntityQueryResult,
    },
    models::ecs::ParentLinkComponent,
};

/// Virtual ECS State that projects action effects as a delta layer over current state
#[derive(Debug, Clone)]
pub struct VirtualEcsState {
    /// User ID for security isolation
    pub user_id: Uuid,
    /// Snapshot of current entity states (baseline)
    pub base_entities: HashMap<Uuid, EntityQueryResult>,
    /// Projected location changes (entity_id -> new_parent_id)
    pub projected_moves: HashMap<Uuid, Uuid>,
    /// Projected component changes (entity_id -> component_type -> component_data)
    pub projected_components: HashMap<Uuid, HashMap<String, serde_json::Value>>,
    /// Projected relationship changes (source_entity, target_entity) -> relationship
    pub projected_relationships: HashMap<(Uuid, Uuid), crate::models::ecs::Relationship>,
    /// Projected inventory changes (entity_id -> inventory_component)
    pub projected_inventories: HashMap<Uuid, crate::models::ecs::InventoryComponent>,
}

impl VirtualEcsState {
    /// Create a new virtual state with baseline entities
    pub fn new(user_id: Uuid, base_entities: Vec<EntityQueryResult>) -> Self {
        let base_map = base_entities.into_iter()
            .map(|entity| (entity.entity.id, entity))
            .collect();

        Self {
            user_id,
            base_entities: base_map,
            projected_moves: HashMap::new(),
            projected_components: HashMap::new(),
            projected_relationships: HashMap::new(),
            projected_inventories: HashMap::new(),
        }
    }

    /// Get entity location, checking projected moves first, then base state
    pub fn get_entity_location(&self, entity_id: Uuid) -> Option<Uuid> {
        // Check projected moves first
        if let Some(projected_location) = self.projected_moves.get(&entity_id) {
            return Some(*projected_location);
        }

        // Fall back to base state
        self.base_entities.get(&entity_id)
            .and_then(|entity| self.extract_parent_from_components(&entity.components))
    }

    /// Get entity component, checking projected changes first, then base state
    pub fn get_entity_component(&self, entity_id: Uuid, component_type: &str) -> Option<serde_json::Value> {
        // Check projected components first
        if let Some(entity_components) = self.projected_components.get(&entity_id) {
            if let Some(component_data) = entity_components.get(component_type) {
                return Some(component_data.clone());
            }
        }

        // Fall back to base state
        self.base_entities.get(&entity_id)
            .and_then(|entity| {
                entity.components.iter()
                    .find(|c| c.component_type == component_type)
                    .map(|c| c.component_data.clone())
            })
    }

    /// Check if entity has a specific component (projected or base)
    pub fn entity_has_component(&self, entity_id: Uuid, component_type: &str) -> bool {
        // Check projected components first
        if let Some(entity_components) = self.projected_components.get(&entity_id) {
            if entity_components.contains_key(component_type) {
                return true;
            }
        }

        // Fall back to base state
        self.base_entities.get(&entity_id)
            .map(|entity| entity.components.iter().any(|c| c.component_type == component_type))
            .unwrap_or(false)
    }

    /// Extract parent ID from ParentLink component
    fn extract_parent_from_components(&self, components: &[crate::models::ecs_diesel::EcsComponent]) -> Option<Uuid> {
        components.iter()
            .find(|c| c.component_type == "ParentLink")
            .and_then(|component| {
                serde_json::from_value::<ParentLinkComponent>(component.component_data.clone())
                    .ok()
                    .map(|parent_link| parent_link.parent_entity_id)
            })
    }
}

/// Service for projecting action effects onto virtual ECS state
pub struct PlanStateProjector {
    ecs_manager: Arc<EcsEntityManager>,
}

impl PlanStateProjector {
    pub fn new(ecs_manager: Arc<EcsEntityManager>) -> Self {
        Self { ecs_manager }
    }

    /// Create virtual state by loading entities referenced in the plan
    #[instrument(skip(self, plan))]
    pub async fn create_virtual_state(
        &self,
        user_id: Uuid,
        plan: &Plan,
    ) -> Result<VirtualEcsState, AppError> {
        debug!("Creating virtual state for plan: {}", plan.goal);

        // Extract all entity IDs referenced in the plan
        let relevant_entities = self.extract_relevant_entities(plan);
        debug!("Found {} relevant entities in plan", relevant_entities.len());

        // Load current state for these entities
        let base_entities = if !relevant_entities.is_empty() {
            self.ecs_manager.get_entities(user_id, &relevant_entities).await?
        } else {
            Vec::new()
        };

        info!("Loaded {} entities for virtual state", base_entities.len());
        Ok(VirtualEcsState::new(user_id, base_entities))
    }

    /// Apply action effects to virtual state (core projection logic)
    #[instrument(skip(self, virtual_state, effects))]
    pub fn apply_action_effects(
        &self,
        virtual_state: &mut VirtualEcsState,
        effects: &Effects,
    ) {
        debug!("Applying action effects to virtual state");

        // Apply EntityMovedEffect
        if let Some(move_effect) = &effects.entity_moved {
            if let (Ok(entity_id), Ok(new_location)) = (
                Uuid::parse_str(&move_effect.entity_id),
                Uuid::parse_str(&move_effect.new_location)
            ) {
                debug!("Projecting move: entity {} -> location {}", entity_id, new_location);
                virtual_state.projected_moves.insert(entity_id, new_location);
            } else {
                warn!("Invalid UUIDs in EntityMovedEffect: entity={}, location={}", 
                      move_effect.entity_id, move_effect.new_location);
            }
        }

        // Apply ComponentUpdateEffect
        if let Some(component_effects) = &effects.component_updated {
            for effect in component_effects {
                if let Ok(entity_id) = Uuid::parse_str(&effect.entity_id) {
                    let entity_components = virtual_state.projected_components
                        .entry(entity_id)
                        .or_insert_with(HashMap::new);

                    match &effect.operation {
                        ComponentOperation::Add | ComponentOperation::Update => {
                            // For basic implementation, we'll use a placeholder value
                            // In a full implementation, this would come from action parameters
                            debug!("Projecting component {:?} operation for entity {}", 
                                   effect.operation, entity_id);
                            entity_components.insert(
                                effect.component_type.clone(),
                                serde_json::json!({"projected": true, "operation": format!("{:?}", effect.operation)})
                            );
                        }
                        ComponentOperation::Remove => {
                            debug!("Projecting component removal: {} from entity {}", 
                                   effect.component_type, entity_id);
                            entity_components.remove(&effect.component_type);
                        }
                    }
                } else {
                    warn!("Invalid entity UUID in ComponentUpdateEffect: {}", effect.entity_id);
                }
            }
        }

        // Apply RelationshipChangeEffect
        if let Some(relationship_effect) = &effects.relationship_changed {
            if let (Ok(source_id), Ok(target_id)) = (
                Uuid::parse_str(&relationship_effect.source_entity),
                Uuid::parse_str(&relationship_effect.target_entity)
            ) {
                debug!("Projecting relationship change: {} -> {}", source_id, target_id);
                
                // For basic implementation, create a minimal relationship
                let relationship = crate::models::ecs::Relationship {
                    target_entity_id: target_id,
                    relationship_type: "projected".to_string(),
                    trust: relationship_effect.trust_change.unwrap_or(0.5),
                    affection: relationship_effect.affection_change.unwrap_or(0.0),
                    metadata: std::collections::HashMap::new(),
                };

                virtual_state.projected_relationships.insert((source_id, target_id), relationship);
            } else {
                warn!("Invalid UUIDs in RelationshipChangeEffect: source={}, target={}", 
                      relationship_effect.source_entity, relationship_effect.target_entity);
            }
        }

        // Apply InventoryChangeEffect
        if let Some(inventory_effect) = &effects.inventory_changed {
            if let Ok(entity_id) = Uuid::parse_str(&inventory_effect.entity_id) {
                debug!("Projecting inventory change for entity {}", entity_id);
                
                // For basic implementation, we'll mark that inventory has changed
                // In a full implementation, this would properly modify inventory items
                let inventory = crate::models::ecs::InventoryComponent {
                    items: Vec::new(), // Simplified for basic implementation
                    capacity: 10,
                };
                
                virtual_state.projected_inventories.insert(entity_id, inventory);
            } else {
                warn!("Invalid entity UUID in InventoryChangeEffect: {}", inventory_effect.entity_id);
            }
        }
    }

    /// Validate preconditions against virtual state
    #[instrument(skip(self, virtual_state, preconditions))]
    pub fn validate_preconditions_against_virtual_state(
        &self,
        virtual_state: &VirtualEcsState,
        preconditions: &Preconditions,
    ) -> Result<(), Vec<ValidationFailure>> {
        let mut failures = Vec::new();

        // Validate entity_at_location preconditions against virtual state
        if let Some(location_checks) = &preconditions.entity_at_location {
            for check in location_checks {
                if let (Ok(entity_id), Ok(expected_location_id)) = (
                    Uuid::parse_str(&check.entity_id),
                    Uuid::parse_str(&check.location_id)
                ) {
                    let actual_location = virtual_state.get_entity_location(entity_id);
                    
                    if actual_location != Some(expected_location_id) {
                        debug!("Entity {} location mismatch: expected {}, actual {:?}", 
                               entity_id, expected_location_id, actual_location);
                        failures.push(ValidationFailure {
                            action_id: "unknown".to_string(),
                            failure_type: ValidationFailureType::PreconditionNotMet,
                            message: format!(
                                "Entity {} not at expected location {} (actual: {:?})", 
                                entity_id, expected_location_id, actual_location
                            ),
                        });
                    } else {
                        debug!("Entity {} location check passed: at {}", entity_id, expected_location_id);
                    }
                } else {
                    failures.push(ValidationFailure {
                        action_id: "unknown".to_string(),
                        failure_type: ValidationFailureType::InvalidParameters,
                        message: format!("Invalid UUID format in location check: entity={}, location={}", 
                                        check.entity_id, check.location_id),
                    });
                }
            }
        }

        // Validate entity_has_component preconditions against virtual state
        if let Some(component_checks) = &preconditions.entity_has_component {
            for check in component_checks {
                if let Ok(entity_id) = Uuid::parse_str(&check.entity_id) {
                    if !virtual_state.entity_has_component(entity_id, &check.component_type) {
                        debug!("Entity {} missing required component: {}", entity_id, check.component_type);
                        failures.push(ValidationFailure {
                            action_id: "unknown".to_string(),
                            failure_type: ValidationFailureType::PreconditionNotMet,
                            message: format!("Entity {} missing component: {}", entity_id, check.component_type),
                        });
                    } else {
                        debug!("Entity {} component check passed: {}", entity_id, check.component_type);
                    }
                } else {
                    failures.push(ValidationFailure {
                        action_id: "unknown".to_string(),
                        failure_type: ValidationFailureType::InvalidParameters,
                        message: format!("Invalid entity UUID in component check: {}", check.entity_id),
                    });
                }
            }
        }

        // Additional precondition types can be added here as needed
        // For Phase 1, we focus on the core ones causing test failures

        if failures.is_empty() {
            debug!("All preconditions validated successfully against virtual state");
            Ok(())
        } else {
            debug!("Virtual state validation failed with {} failures", failures.len());
            Err(failures)
        }
    }

    /// Extract entity IDs referenced in plan actions and preconditions
    fn extract_relevant_entities(&self, plan: &Plan) -> Vec<Uuid> {
        let mut entity_ids = std::collections::HashSet::new();

        for action in &plan.actions {
            // Extract from action parameters
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
            self.extract_entities_from_preconditions(&action.preconditions, &mut entity_ids);
        }

        entity_ids.into_iter().collect()
    }

    /// Helper to extract entity IDs from preconditions
    fn extract_entities_from_preconditions(
        &self,
        preconditions: &Preconditions,
        entity_ids: &mut std::collections::HashSet<Uuid>,
    ) {
        // Extract from entity_exists checks
        if let Some(checks) = &preconditions.entity_exists {
            for check in checks {
                if let Some(id_str) = &check.entity_id {
                    if let Ok(entity_id) = Uuid::parse_str(id_str) {
                        entity_ids.insert(entity_id);
                    }
                }
            }
        }

        // Extract from entity_at_location checks
        if let Some(checks) = &preconditions.entity_at_location {
            for check in checks {
                if let Ok(entity_id) = Uuid::parse_str(&check.entity_id) {
                    entity_ids.insert(entity_id);
                }
                if let Ok(location_id) = Uuid::parse_str(&check.location_id) {
                    entity_ids.insert(location_id);
                }
            }
        }

        // Extract from entity_has_component checks
        if let Some(checks) = &preconditions.entity_has_component {
            for check in checks {
                if let Ok(entity_id) = Uuid::parse_str(&check.entity_id) {
                    entity_ids.insert(entity_id);
                }
            }
        }

        // Extract from inventory_has_space checks
        if let Some(check) = &preconditions.inventory_has_space {
            if let Ok(entity_id) = Uuid::parse_str(&check.entity_id) {
                entity_ids.insert(entity_id);
            }
        }

        // Extract from relationship_exists checks
        if let Some(checks) = &preconditions.relationship_exists {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ecs_diesel::{EcsEntity, EcsComponent};
    use chrono::Utc;

    fn create_test_entity_result(entity_id: Uuid, user_id: Uuid, name: &str) -> EntityQueryResult {
        EntityQueryResult {
            entity: crate::models::ecs_diesel::EcsEntity {
                id: entity_id,
                user_id,
                archetype_signature: "Name".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            components: vec![
                crate::models::ecs_diesel::EcsComponent {
                    id: Uuid::new_v4(),
                    entity_id,
                    user_id,
                    component_type: "Name".to_string(),
                    component_data: serde_json::json!({"name": name}),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    encrypted_component_data: None,
                    component_data_nonce: None,
                }
            ],
            cache_hit: false,
            cache_key: format!("test:{}", entity_id),
        }
    }

    #[test]
    fn test_virtual_ecs_state_creation() {
        let user_id = Uuid::new_v4();
        let entity_id = Uuid::new_v4();
        let entity_result = create_test_entity_result(entity_id, user_id, "TestEntity");

        let virtual_state = VirtualEcsState::new(user_id, vec![entity_result]);

        assert_eq!(virtual_state.user_id, user_id);
        assert_eq!(virtual_state.base_entities.len(), 1);
        assert!(virtual_state.base_entities.contains_key(&entity_id));
        assert!(virtual_state.projected_moves.is_empty());
        assert!(virtual_state.projected_components.is_empty());
    }

    #[test]
    fn test_entity_location_projection() {
        let user_id = Uuid::new_v4();
        let entity_id = Uuid::new_v4();
        let new_location = Uuid::new_v4();
        let entity_result = create_test_entity_result(entity_id, user_id, "TestEntity");

        let mut virtual_state = VirtualEcsState::new(user_id, vec![entity_result]);

        // Initially no projected location
        assert_eq!(virtual_state.get_entity_location(entity_id), None);

        // Add projected move
        virtual_state.projected_moves.insert(entity_id, new_location);

        // Should return projected location
        assert_eq!(virtual_state.get_entity_location(entity_id), Some(new_location));
    }

    #[test]
    fn test_component_projection() {
        let user_id = Uuid::new_v4();
        let entity_id = Uuid::new_v4();
        let entity_result = create_test_entity_result(entity_id, user_id, "TestEntity");

        let mut virtual_state = VirtualEcsState::new(user_id, vec![entity_result]);

        // Initially has Name component from base state
        assert!(virtual_state.entity_has_component(entity_id, "Name"));
        assert!(!virtual_state.entity_has_component(entity_id, "NewComponent"));

        // Add projected component
        let mut entity_components = HashMap::new();
        entity_components.insert("NewComponent".to_string(), serde_json::json!({"test": true}));
        virtual_state.projected_components.insert(entity_id, entity_components);

        // Should have both base and projected components
        assert!(virtual_state.entity_has_component(entity_id, "Name"));
        assert!(virtual_state.entity_has_component(entity_id, "NewComponent"));
    }
}