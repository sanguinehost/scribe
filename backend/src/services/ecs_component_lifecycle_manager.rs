// backend/src/services/ecs_component_lifecycle_manager.rs
//
// ECS Component Lifecycle Manager
//
// This service handles component lifecycle operations including validation,
// dependencies, and atomic updates to maintain data integrity.

use std::sync::Arc;
use uuid::Uuid;
use serde_json::{Value as JsonValue, json};
use tracing::{info, debug, instrument};
use std::collections::{HashMap, HashSet};

use crate::{
    PgPool,
    errors::AppError,
    models::ecs_diesel::EcsComponent,
    services::{EcsEntityManager, ComponentUpdate, ComponentOperation},
};

/// Component validation rule
pub struct ComponentValidationRule {
    pub component_type: String,
    pub required_fields: Vec<String>,
    pub field_validators: HashMap<String, Box<dyn Fn(&JsonValue) -> Result<(), String> + Send + Sync>>,
    pub dependencies: Vec<String>, // Component types that must exist
    pub conflicts: Vec<String>,    // Component types that cannot coexist
}

impl std::fmt::Debug for ComponentValidationRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComponentValidationRule")
            .field("component_type", &self.component_type)
            .field("required_fields", &self.required_fields)
            .field("field_validators", &format!("<{} validators>", self.field_validators.len()))
            .field("dependencies", &self.dependencies)
            .field("conflicts", &self.conflicts)
            .finish()
    }
}

impl Clone for ComponentValidationRule {
    fn clone(&self) -> Self {
        // Note: field_validators cannot be cloned due to dyn Fn trait objects
        // This will create a new rule with empty validators
        Self {
            component_type: self.component_type.clone(),
            required_fields: self.required_fields.clone(),
            field_validators: HashMap::new(),
            dependencies: self.dependencies.clone(),
            conflicts: self.conflicts.clone(),
        }
    }
}

/// Component dependency resolution result
#[derive(Debug, Clone)]
pub struct DependencyResolution {
    pub missing_dependencies: Vec<String>,
    pub conflicting_components: Vec<String>,
    pub suggested_order: Vec<ComponentUpdate>,
}

/// Component lifecycle operation result
#[derive(Debug, Clone)]
pub struct LifecycleOperationResult {
    pub success: bool,
    pub components_affected: Vec<EcsComponent>,
    pub validation_errors: Vec<String>,
    pub dependency_issues: Vec<String>,
    pub warnings: Vec<String>,
}

/// Configuration for component lifecycle management
#[derive(Debug, Clone)]
pub struct ComponentLifecycleConfig {
    /// Enable strict validation of component data
    pub strict_validation: bool,
    /// Enable dependency checking
    pub check_dependencies: bool,
    /// Enable conflict detection
    pub check_conflicts: bool,
    /// Maximum components per entity
    pub max_components_per_entity: usize,
    /// Maximum component data size (bytes)
    pub max_component_size: usize,
}

impl Default for ComponentLifecycleConfig {
    fn default() -> Self {
        Self {
            strict_validation: true,
            check_dependencies: true,
            check_conflicts: true,
            max_components_per_entity: 50,
            max_component_size: 1_048_576, // 1MB
        }
    }
}

/// Component Lifecycle Manager with validation and dependency management
pub struct EcsComponentLifecycleManager {
    _db_pool: Arc<PgPool>, // TODO: Use for direct DB operations in future iterations
    entity_manager: Arc<EcsEntityManager>,
    config: ComponentLifecycleConfig,
    validation_rules: HashMap<String, ComponentValidationRule>,
}

impl EcsComponentLifecycleManager {
    /// Create a new component lifecycle manager
    pub fn new(
        db_pool: Arc<PgPool>,
        entity_manager: Arc<EcsEntityManager>,
        config: Option<ComponentLifecycleConfig>,
    ) -> Self {
        let config = config.unwrap_or_default();
        let mut manager = Self {
            _db_pool: db_pool,
            entity_manager,
            config,
            validation_rules: HashMap::new(),
        };
        
        // Register default validation rules
        manager.register_default_validation_rules();
        
        info!("Initialized ECS Component Lifecycle Manager with config: {:?}", manager.config);
        manager
    }

    /// Add or update a component with full lifecycle management
    #[instrument(skip(self, component_data), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn add_component(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
        component_type: String,
        component_data: JsonValue,
    ) -> Result<LifecycleOperationResult, AppError> {
        debug!("Adding component {} to entity {}", component_type, entity_id);

        // Step 1: Validate component data
        let validation_errors = self.validate_component_data(&component_type, &component_data)?;
        if !validation_errors.is_empty() && self.config.strict_validation {
            return Ok(LifecycleOperationResult {
                success: false,
                components_affected: Vec::new(),
                validation_errors,
                dependency_issues: Vec::new(),
                warnings: Vec::new(),
            });
        }

        // Step 2: Check dependencies and conflicts
        let dependency_resolution = self.resolve_dependencies(user_id, entity_id, &component_type).await?;
        
        if !dependency_resolution.missing_dependencies.is_empty() ||
           !dependency_resolution.conflicting_components.is_empty() {
            if self.config.check_dependencies || self.config.check_conflicts {
                return Ok(LifecycleOperationResult {
                    success: false,
                    components_affected: Vec::new(),
                    validation_errors,
                    dependency_issues: vec![
                        format!("Missing dependencies: {:?}", dependency_resolution.missing_dependencies),
                        format!("Conflicting components: {:?}", dependency_resolution.conflicting_components),
                    ],
                    warnings: Vec::new(),
                });
            }
        }

        // Step 3: Check entity component limits
        let current_components = self.get_entity_components(user_id, entity_id).await?;
        if current_components.len() >= self.config.max_components_per_entity {
            return Ok(LifecycleOperationResult {
                success: false,
                components_affected: Vec::new(),
                validation_errors: vec![format!(
                    "Entity has reached maximum component limit of {}",
                    self.config.max_components_per_entity
                )],
                dependency_issues: Vec::new(),
                warnings: Vec::new(),
            });
        }

        // Step 4: Check component size
        let component_size = serde_json::to_string(&component_data)
            .map_err(|e| AppError::SerializationError(e.to_string()))?
            .len();
        
        if component_size > self.config.max_component_size {
            return Ok(LifecycleOperationResult {
                success: false,
                components_affected: Vec::new(),
                validation_errors: vec![format!(
                    "Component data size ({} bytes) exceeds maximum allowed size ({} bytes)",
                    component_size, self.config.max_component_size
                )],
                dependency_issues: Vec::new(),
                warnings: Vec::new(),
            });
        }

        // Step 5: Add the component
        let updates = vec![ComponentUpdate {
            entity_id,
            component_type: component_type.clone(),
            component_data,
            operation: ComponentOperation::Add,
        }];

        let updated_components = self.entity_manager.update_components(user_id, entity_id, updates).await?;

        info!("Successfully added component {} to entity {}", component_type, entity_id);

        Ok(LifecycleOperationResult {
            success: true,
            components_affected: updated_components,
            validation_errors,
            dependency_issues: Vec::new(),
            warnings: Vec::new(),
        })
    }

    /// Update a component with validation
    #[instrument(skip(self, component_data), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn update_component(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
        component_type: String,
        component_data: JsonValue,
    ) -> Result<LifecycleOperationResult, AppError> {
        debug!("Updating component {} on entity {}", component_type, entity_id);

        // Validate component data
        let validation_errors = self.validate_component_data(&component_type, &component_data)?;
        if !validation_errors.is_empty() && self.config.strict_validation {
            return Ok(LifecycleOperationResult {
                success: false,
                components_affected: Vec::new(),
                validation_errors,
                dependency_issues: Vec::new(),
                warnings: Vec::new(),
            });
        }

        // Check component size
        let component_size = serde_json::to_string(&component_data)
            .map_err(|e| AppError::SerializationError(e.to_string()))?
            .len();
        
        if component_size > self.config.max_component_size {
            return Ok(LifecycleOperationResult {
                success: false,
                components_affected: Vec::new(),
                validation_errors: vec![format!(
                    "Component data size ({} bytes) exceeds maximum allowed size ({} bytes)",
                    component_size, self.config.max_component_size
                )],
                dependency_issues: Vec::new(),
                warnings: Vec::new(),
            });
        }

        // Update the component
        let updates = vec![ComponentUpdate {
            entity_id,
            component_type: component_type.clone(),
            component_data,
            operation: ComponentOperation::Update,
        }];

        let updated_components = self.entity_manager.update_components(user_id, entity_id, updates).await?;

        info!("Successfully updated component {} on entity {}", component_type, entity_id);

        Ok(LifecycleOperationResult {
            success: true,
            components_affected: updated_components,
            validation_errors,
            dependency_issues: Vec::new(),
            warnings: Vec::new(),
        })
    }

    /// Remove a component with dependency checking
    #[instrument(skip(self), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id))))]
    pub async fn remove_component(
        &self,
        user_id: Uuid,
        entity_id: Uuid,
        component_type: String,
    ) -> Result<LifecycleOperationResult, AppError> {
        debug!("Removing component {} from entity {}", component_type, entity_id);

        // Check if other components depend on this one
        let dependency_issues = self.check_removal_dependencies(user_id, entity_id, &component_type).await?;
        
        if !dependency_issues.is_empty() && self.config.check_dependencies {
            return Ok(LifecycleOperationResult {
                success: false,
                components_affected: Vec::new(),
                validation_errors: Vec::new(),
                dependency_issues,
                warnings: Vec::new(),
            });
        }

        // Remove the component
        let updates = vec![ComponentUpdate {
            entity_id,
            component_type: component_type.clone(),
            component_data: json!({}), // Empty data for removal
            operation: ComponentOperation::Remove,
        }];

        let _updated_components = self.entity_manager.update_components(user_id, entity_id, updates).await?;

        info!("Successfully removed component {} from entity {}", component_type, entity_id);

        Ok(LifecycleOperationResult {
            success: true,
            components_affected: Vec::new(), // Component was removed
            validation_errors: Vec::new(),
            dependency_issues: Vec::new(),
            warnings: dependency_issues, // Show as warnings instead of errors
        })
    }

    /// Perform bulk component operations atomically
    #[instrument(skip(self, operations), fields(user_hash = %format!("{:x}", Self::hash_user_id(user_id)), operations_count = operations.len()))]
    pub async fn bulk_component_operations(
        &self,
        user_id: Uuid,
        operations: Vec<ComponentUpdate>,
    ) -> Result<LifecycleOperationResult, AppError> {
        debug!("Performing {} bulk component operations", operations.len());

        let mut all_validation_errors = Vec::new();
        let mut all_dependency_issues = Vec::new();
        let warnings = Vec::new();

        // Group operations by entity
        let mut operations_by_entity: HashMap<Uuid, Vec<ComponentUpdate>> = HashMap::new();
        for op in operations {
            operations_by_entity.entry(op.entity_id).or_insert_with(Vec::new).push(op);
        }

        // Validate all operations first
        for (entity_id, entity_ops) in &operations_by_entity {
            for op in entity_ops {
                if !matches!(op.operation, ComponentOperation::Remove) {
                    let validation_errors = self.validate_component_data(&op.component_type, &op.component_data)?;
                    all_validation_errors.extend(validation_errors);
                }

                // Check dependencies for each operation
                match op.operation {
                    ComponentOperation::Add => {
                        let dep_resolution = self.resolve_dependencies(user_id, *entity_id, &op.component_type).await?;
                        if !dep_resolution.missing_dependencies.is_empty() {
                            all_dependency_issues.push(format!(
                                "Entity {}: Missing dependencies for {}: {:?}",
                                entity_id, op.component_type, dep_resolution.missing_dependencies
                            ));
                        }
                        if !dep_resolution.conflicting_components.is_empty() {
                            all_dependency_issues.push(format!(
                                "Entity {}: Conflicting components for {}: {:?}",
                                entity_id, op.component_type, dep_resolution.conflicting_components
                            ));
                        }
                    }
                    ComponentOperation::Remove => {
                        let dep_issues = self.check_removal_dependencies(user_id, *entity_id, &op.component_type).await?;
                        all_dependency_issues.extend(dep_issues);
                    }
                    ComponentOperation::Update => {
                        // Update operations generally safe from dependency perspective
                    }
                }
            }
        }

        // If validation fails and strict mode is on, abort
        if !all_validation_errors.is_empty() && self.config.strict_validation {
            return Ok(LifecycleOperationResult {
                success: false,
                components_affected: Vec::new(),
                validation_errors: all_validation_errors,
                dependency_issues: all_dependency_issues,
                warnings,
            });
        }

        // If dependency issues and checking is enabled, abort
        if !all_dependency_issues.is_empty() && (self.config.check_dependencies || self.config.check_conflicts) {
            return Ok(LifecycleOperationResult {
                success: false,
                components_affected: Vec::new(),
                validation_errors: all_validation_errors,
                dependency_issues: all_dependency_issues,
                warnings,
            });
        }

        // Execute all operations
        let mut all_affected_components = Vec::new();
        for (entity_id, entity_ops) in operations_by_entity {
            let updated_components = self.entity_manager.update_components(user_id, entity_id, entity_ops).await?;
            all_affected_components.extend(updated_components);
        }

        info!("Successfully completed {} bulk component operations", all_affected_components.len());

        Ok(LifecycleOperationResult {
            success: true,
            components_affected: all_affected_components,
            validation_errors: all_validation_errors,
            dependency_issues: Vec::new(),
            warnings,
        })
    }

    // Private helper methods

    fn register_default_validation_rules(&mut self) {
        // Health component validation
        let health_rule = ComponentValidationRule {
            component_type: "Health".to_string(),
            required_fields: vec!["current".to_string(), "max".to_string()],
            field_validators: {
                let mut validators = HashMap::new();
                validators.insert("current".to_string(), Box::new(|v: &JsonValue| {
                    if let Some(current) = v.as_i64() {
                        if current >= 0 { Ok(()) } else { Err("Current health must be non-negative".to_string()) }
                    } else {
                        Err("Current health must be a number".to_string())
                    }
                }) as Box<dyn Fn(&JsonValue) -> Result<(), String> + Send + Sync>);
                
                validators.insert("max".to_string(), Box::new(|v: &JsonValue| {
                    if let Some(max) = v.as_i64() {
                        if max > 0 { Ok(()) } else { Err("Max health must be positive".to_string()) }
                    } else {
                        Err("Max health must be a number".to_string())
                    }
                }) as Box<dyn Fn(&JsonValue) -> Result<(), String> + Send + Sync>);
                
                validators
            },
            dependencies: Vec::new(),
            conflicts: Vec::new(),
        };
        self.validation_rules.insert("Health".to_string(), health_rule);

        // Position component validation
        let position_rule = ComponentValidationRule {
            component_type: "Position".to_string(),
            required_fields: vec!["x".to_string(), "y".to_string(), "z".to_string(), "zone".to_string()],
            field_validators: HashMap::new(), // Basic numeric validation handled by serde
            dependencies: Vec::new(),
            conflicts: Vec::new(),
        };
        self.validation_rules.insert("Position".to_string(), position_rule);

        // Inventory component validation
        let inventory_rule = ComponentValidationRule {
            component_type: "Inventory".to_string(),
            required_fields: vec!["items".to_string(), "capacity".to_string()],
            field_validators: {
                let mut validators = HashMap::new();
                validators.insert("capacity".to_string(), Box::new(|v: &JsonValue| {
                    if let Some(capacity) = v.as_u64() {
                        if capacity > 0 && capacity <= 1000 { 
                            Ok(()) 
                        } else { 
                            Err("Capacity must be between 1 and 1000".to_string()) 
                        }
                    } else {
                        Err("Capacity must be a positive number".to_string())
                    }
                }) as Box<dyn Fn(&JsonValue) -> Result<(), String> + Send + Sync>);
                validators
            },
            dependencies: Vec::new(),
            conflicts: Vec::new(),
        };
        self.validation_rules.insert("Inventory".to_string(), inventory_rule);

        // Relationships component validation
        let relationships_rule = ComponentValidationRule {
            component_type: "Relationships".to_string(),
            required_fields: vec!["relationships".to_string()],
            field_validators: HashMap::new(),
            dependencies: Vec::new(),
            conflicts: Vec::new(),
        };
        self.validation_rules.insert("Relationships".to_string(), relationships_rule);
    }

    fn validate_component_data(&self, component_type: &str, data: &JsonValue) -> Result<Vec<String>, AppError> {
        let mut errors = Vec::new();

        if let Some(rule) = self.validation_rules.get(component_type) {
            // Check required fields
            for required_field in &rule.required_fields {
                if !data.get(required_field).is_some() {
                    errors.push(format!("Missing required field: {}", required_field));
                }
            }

            // Run field validators
            for (field, validator) in &rule.field_validators {
                if let Some(field_value) = data.get(field) {
                    if let Err(validation_error) = validator(field_value) {
                        errors.push(format!("Field {} validation failed: {}", field, validation_error));
                    }
                }
            }
        }

        Ok(errors)
    }

    async fn resolve_dependencies(&self, user_id: Uuid, entity_id: Uuid, component_type: &str) -> Result<DependencyResolution, AppError> {
        let mut missing_dependencies = Vec::new();
        let mut conflicting_components = Vec::new();

        if let Some(rule) = self.validation_rules.get(component_type) {
            // Get existing components for this entity
            let existing_components = self.get_entity_components(user_id, entity_id).await?;
            let existing_types: HashSet<String> = existing_components
                .iter()
                .map(|c| c.component_type.clone())
                .collect();

            // Check dependencies
            for dependency in &rule.dependencies {
                if !existing_types.contains(dependency) {
                    missing_dependencies.push(dependency.clone());
                }
            }

            // Check conflicts
            for conflict in &rule.conflicts {
                if existing_types.contains(conflict) {
                    conflicting_components.push(conflict.clone());
                }
            }
        }

        Ok(DependencyResolution {
            missing_dependencies,
            conflicting_components,
            suggested_order: Vec::new(), // TODO: Implement dependency ordering
        })
    }

    async fn check_removal_dependencies(&self, user_id: Uuid, entity_id: Uuid, component_type: &str) -> Result<Vec<String>, AppError> {
        let mut dependency_issues = Vec::new();

        // Get existing components for this entity
        let existing_components = self.get_entity_components(user_id, entity_id).await?;
        
        // Check if any existing component depends on the one being removed
        for component in &existing_components {
            if let Some(rule) = self.validation_rules.get(&component.component_type) {
                if rule.dependencies.contains(&component_type.to_string()) {
                    dependency_issues.push(format!(
                        "Component {} depends on {} and cannot be removed",
                        component.component_type, component_type
                    ));
                }
            }
        }

        Ok(dependency_issues)
    }

    async fn get_entity_components(&self, user_id: Uuid, entity_id: Uuid) -> Result<Vec<EcsComponent>, AppError> {
        if let Some(entity_result) = self.entity_manager.get_entity(user_id, entity_id).await? {
            Ok(entity_result.components)
        } else {
            Ok(Vec::new())
        }
    }

    fn hash_user_id(user_id: Uuid) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        user_id.hash(&mut hasher);
        hasher.finish()
    }
}