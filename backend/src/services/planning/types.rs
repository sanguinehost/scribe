use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Root structure for an LLM-generated plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiGeneratedPlan {
    pub plan: Plan,
}

/// A complete plan with goal, actions, and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub goal: String,
    pub actions: Vec<PlannedAction>,
    pub metadata: PlanMetadata,
}

/// Metadata about the plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanMetadata {
    pub estimated_duration: Option<u64>,
    pub confidence: f32,
    pub alternative_considered: Option<String>,
}

/// A single action within a plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedAction {
    pub id: String,
    pub name: ActionName,
    pub parameters: serde_json::Value,
    pub preconditions: Preconditions,
    pub effects: Effects,
    pub dependencies: Vec<String>,
}

/// Enumeration of all available actions (matching Tactical Toolkit)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ActionName {
    FindEntity,
    GetEntityDetails,
    CreateEntity,
    UpdateEntity,
    MoveEntity,
    GetContainedEntities,
    GetSpatialContext,
    AddItemToInventory,
    RemoveItemFromInventory,
    UpdateRelationship,
}

impl std::fmt::Display for ActionName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActionName::FindEntity => write!(f, "find_entity"),
            ActionName::GetEntityDetails => write!(f, "get_entity_details"),
            ActionName::CreateEntity => write!(f, "create_entity"),
            ActionName::UpdateEntity => write!(f, "update_entity"),
            ActionName::MoveEntity => write!(f, "move_entity"),
            ActionName::GetContainedEntities => write!(f, "get_contained_entities"),
            ActionName::GetSpatialContext => write!(f, "get_spatial_context"),
            ActionName::AddItemToInventory => write!(f, "add_item_to_inventory"),
            ActionName::RemoveItemFromInventory => write!(f, "remove_item_from_inventory"),
            ActionName::UpdateRelationship => write!(f, "update_relationship"),
        }
    }
}

/// Preconditions that must be met before action execution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Preconditions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_exists: Option<Vec<EntityExistenceCheck>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_at_location: Option<Vec<EntityLocationCheck>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_has_component: Option<Vec<EntityComponentCheck>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_has_space: Option<InventorySpaceCheck>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship_exists: Option<Vec<RelationshipCheck>>,
}

/// Check if an entity exists
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityExistenceCheck {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_name: Option<String>,
}

/// Check if an entity is at a specific location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityLocationCheck {
    pub entity_id: String,
    pub location_id: String,
}

/// Check if an entity has a specific component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityComponentCheck {
    pub entity_id: String,
    pub component_type: String,
}

/// Check if inventory has required space
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventorySpaceCheck {
    pub entity_id: String,
    pub required_slots: u32,
}

/// Check if a relationship exists with minimum trust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipCheck {
    pub source_entity: String,
    pub target_entity: String,
    pub min_trust: Option<f32>,
}

/// Effects that result from successful action execution
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Effects {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_moved: Option<EntityMovedEffect>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_created: Option<EntityCreatedEffect>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component_updated: Option<Vec<ComponentUpdateEffect>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_changed: Option<InventoryChangeEffect>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship_changed: Option<RelationshipChangeEffect>,
}

/// Effect: Entity moved to new location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityMovedEffect {
    pub entity_id: String,
    pub new_location: String,
}

/// Effect: New entity created
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityCreatedEffect {
    pub entity_name: String,
    pub entity_type: String,
    pub parent_id: Option<String>,
}

/// Effect: Component updated on entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentUpdateEffect {
    pub entity_id: String,
    pub component_type: String,
    pub operation: ComponentOperation,
}

/// Component operation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ComponentOperation {
    Add,
    Update,
    Remove,
}

/// Effect: Inventory quantity changed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryChangeEffect {
    pub entity_id: String,
    pub item_id: String,
    pub quantity_change: i32,
}

/// Effect: Relationship values changed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipChangeEffect {
    pub source_entity: String,
    pub target_entity: String,
    pub trust_change: Option<f32>,
    pub affection_change: Option<f32>,
}

/// Result of plan validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlanValidationResult {
    Valid(ValidatedPlan),
    Invalid(InvalidPlan),
}

/// A plan that has passed all validation checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatedPlan {
    pub plan_id: Uuid,
    pub original_plan: Plan,
    pub validation_timestamp: DateTime<Utc>,
    pub cache_key: String,
}

/// A plan that failed validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidPlan {
    pub plan: Plan,
    pub failures: Vec<ValidationFailure>,
}

/// Specific validation failure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationFailure {
    pub action_id: String,
    pub failure_type: ValidationFailureType,
    pub message: String,
}

/// Types of validation failures
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidationFailureType {
    ActionNotFound,
    InvalidParameters,
    EntityNotFound,
    PreconditionNotMet,
    InvalidDependency,
    PermissionDenied,
}

/// Cached entity state for context window optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedEntityState {
    pub entity_id: Uuid,
    pub name: String,
    pub components: HashMap<String, serde_json::Value>,
    pub last_accessed: DateTime<Utc>,
    pub access_count: u32,
}

/// Context cache for avoiding repeated queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextCache {
    pub recent_entities: HashMap<Uuid, CachedEntityState>,
    pub recent_plans: Vec<(String, ValidatedPlan)>,
    pub cache_timestamp: DateTime<Utc>,
}