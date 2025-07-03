// backend/src/services/event_valence_processor.rs
//
// Event Valence Processing Service
//
// This service handles the processing of emotional and relational valence changes
// from chronicle events, converting them into ECS component and relationship updates.

use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;
use tracing::{info, warn, debug, instrument};
use chrono::Utc;

use crate::{
    PgPool,
    errors::AppError,
    models::{
        narrative_ontology::{EventValence, ValenceType},
        ecs_diesel::{EcsComponent, NewEcsComponent, EcsEntityRelationship, NewEcsEntityRelationship},
    },
    schema::{ecs_components, ecs_entity_relationships},
};

use diesel::prelude::*;

/// Result of processing valence changes
#[derive(Debug, Clone)]
pub struct ValenceProcessingResult {
    /// Component updates that were applied (for individual entity attributes)
    pub component_updates: Vec<ComponentValenceUpdate>,
    /// Relationship updates that were applied (for inter-entity relationships)
    pub relationship_updates: Vec<RelationshipValenceUpdate>,
    /// History records for auditing
    pub history_records: Vec<ValenceHistoryRecord>,
    /// Any warnings or issues encountered during processing
    pub messages: Vec<String>,
}

/// Represents a component update from valence processing
#[derive(Debug, Clone)]
pub struct ComponentValenceUpdate {
    pub entity_id: Uuid,
    pub component_type: String,
    pub attribute: String,
    pub previous_value: f32,
    pub new_value: f32,
    pub change_amount: f32,
    pub valence_type: ValenceType,
}

/// Represents a relationship update from valence processing
#[derive(Debug, Clone)]
pub struct RelationshipValenceUpdate {
    pub from_entity_id: Uuid,
    pub to_entity_id: Uuid,
    pub relationship_type: String,
    pub attribute: String,
    pub previous_value: f32,
    pub new_value: f32,
    pub change_amount: f32,
    pub valence_type: ValenceType,
}

/// Audit record for valence change history
#[derive(Debug, Clone)]
pub struct ValenceHistoryRecord {
    pub source_entity_id: Uuid,
    pub target_entity_id: Uuid,
    pub valence_type: ValenceType,
    pub change_amount: f32,
    pub reason: Option<String>,
    pub timestamp: chrono::DateTime<Utc>,
    pub event_id: Option<Uuid>,
}

/// Configuration for valence processing behavior
#[derive(Debug, Clone)]
pub struct ValenceProcessingConfig {
    /// Minimum change threshold to apply (prevents noise)
    pub min_change_threshold: f32,
    /// Maximum change per single event (prevents massive swings)
    pub max_change_per_event: f32,
    /// Whether to clamp values to [-1.0, 1.0] range
    pub clamp_values: bool,
    /// Whether to create history records
    pub track_history: bool,
}

impl Default for ValenceProcessingConfig {
    fn default() -> Self {
        Self {
            min_change_threshold: 0.01,
            max_change_per_event: 1.0,
            clamp_values: true,
            track_history: true,
        }
    }
}

/// Service for processing valence changes from chronicle events
pub struct EventValenceProcessor {
    db_pool: Arc<PgPool>,
    config: ValenceProcessingConfig,
}

impl EventValenceProcessor {
    /// Create a new valence processor with default configuration
    pub fn new(db_pool: Arc<PgPool>) -> Self {
        Self {
            db_pool,
            config: ValenceProcessingConfig::default(),
        }
    }

    /// Create a new valence processor with custom configuration
    pub fn with_config(db_pool: Arc<PgPool>, config: ValenceProcessingConfig) -> Self {
        Self {
            db_pool,
            config,
        }
    }

    /// Process valence changes for entities, returning the applied updates
    #[instrument(skip(self, valence_changes), fields(changes_count = valence_changes.len()))]
    pub async fn process_valence_changes(
        &self,
        valence_changes: &[EventValence],
        source_entity_id: Option<Uuid>,
        event_id: Option<Uuid>,
        user_id: Uuid,
    ) -> Result<ValenceProcessingResult, AppError> {
        debug!("Processing {} valence changes", valence_changes.len());

        let mut result = ValenceProcessingResult {
            component_updates: Vec::new(),
            relationship_updates: Vec::new(),
            history_records: Vec::new(),
            messages: Vec::new(),
        };

        for valence in valence_changes {
            // Apply change threshold filtering
            if valence.change.abs() < self.config.min_change_threshold {
                debug!("Skipping valence change below threshold: {}", valence.change);
                continue;
            }

            // Clamp change amount if configured
            let clamped_change = if self.config.max_change_per_event > 0.0 {
                valence.change.max(-self.config.max_change_per_event)
                    .min(self.config.max_change_per_event)
            } else {
                valence.change
            };

            match self.determine_valence_scope(&valence.valence_type) {
                ValenceScope::Individual => {
                    self.process_individual_valence(valence, clamped_change, event_id, &mut result).await?;
                }
                ValenceScope::Relational => {
                    let source_id = source_entity_id.unwrap_or(valence.target);
                    self.process_relational_valence(valence, source_id, clamped_change, event_id, &mut result).await?;
                }
            }

            // Create history record if configured
            if self.config.track_history {
                result.history_records.push(ValenceHistoryRecord {
                    source_entity_id: source_entity_id.unwrap_or(valence.target),
                    target_entity_id: valence.target,
                    valence_type: valence.valence_type.clone(),
                    change_amount: clamped_change,
                    reason: valence.description.clone(),
                    timestamp: Utc::now(),
                    event_id,
                });
            }
        }

        // Persist all changes to database
        self.persist_valence_changes(&result, user_id).await?;

        info!("Valence processing completed: {} component updates, {} relationship updates",
            result.component_updates.len(), result.relationship_updates.len());

        Ok(result)
    }

    /// Determine whether a component value should be clamped to [-1.0, 1.0]
    fn should_clamp_component_value(&self, valence_type: &ValenceType) -> bool {
        match valence_type {
            // Health, wealth, power, knowledge should not be clamped to [-1.0, 1.0]
            ValenceType::Health | 
            ValenceType::Wealth | 
            ValenceType::Power | 
            ValenceType::Knowledge => false,
            
            // Reputation can be clamped as it represents a normalized score
            ValenceType::Reputation => true,
            
            // Relational values are handled separately, but custom might need clamping
            _ => true,
        }
    }

    /// Determine whether a valence type affects individual entities or relationships
    fn determine_valence_scope(&self, valence_type: &ValenceType) -> ValenceScope {
        match valence_type {
            // Individual attributes - affect the entity itself
            ValenceType::Health | 
            ValenceType::Power | 
            ValenceType::Knowledge | 
            ValenceType::Wealth | 
            ValenceType::Reputation => ValenceScope::Individual,
            
            // Relational attributes - affect relationships between entities
            ValenceType::Trust | 
            ValenceType::Affection | 
            ValenceType::Respect | 
            ValenceType::Fear => ValenceScope::Relational,
            
            // Custom types default to relational
            ValenceType::Custom(_) => ValenceScope::Relational,
        }
    }

    /// Process valence changes that affect individual entity attributes
    async fn process_individual_valence(
        &self,
        valence: &EventValence,
        change_amount: f32,
        _event_id: Option<Uuid>,
        result: &mut ValenceProcessingResult,
    ) -> Result<(), AppError> {
        let component_type = self.get_component_type_for_valence(&valence.valence_type);
        let attribute = self.get_attribute_name_for_valence(&valence.valence_type);

        // Get current component value
        let current_value = self.get_current_component_value(valence.target, &component_type, &attribute).await?;
        
        // Calculate new value
        let new_value = if self.config.clamp_values && self.should_clamp_component_value(&valence.valence_type) {
            (current_value + change_amount).max(-1.0).min(1.0)
        } else {
            current_value + change_amount
        };


        // Record the update
        result.component_updates.push(ComponentValenceUpdate {
            entity_id: valence.target,
            component_type: component_type.clone(),
            attribute: attribute.clone(),
            previous_value: current_value,
            new_value,
            change_amount,
            valence_type: valence.valence_type.clone(),
        });

        debug!("Individual valence update: {} {} {} -> {} (change: {})",
            valence.target, component_type, attribute, new_value, change_amount);

        Ok(())
    }

    /// Process valence changes that affect relationships between entities
    async fn process_relational_valence(
        &self,
        valence: &EventValence,
        source_entity_id: Uuid,
        change_amount: f32,
        _event_id: Option<Uuid>,
        result: &mut ValenceProcessingResult,
    ) -> Result<(), AppError> {
        if source_entity_id == valence.target {
            warn!("Skipping self-referential valence change for entity {}", valence.target);
            result.messages.push(format!("Skipped self-referential valence change for entity {}", valence.target));
            return Ok(());
        }

        let relationship_type = self.get_relationship_type_for_valence(&valence.valence_type);
        let attribute = self.get_attribute_name_for_valence(&valence.valence_type);

        // Get current relationship value
        let current_value = self.get_current_relationship_value(
            source_entity_id, 
            valence.target, 
            &relationship_type, 
            &attribute
        ).await?;

        // Calculate new value
        let new_value = if self.config.clamp_values {
            (current_value + change_amount).max(-1.0).min(1.0)
        } else {
            current_value + change_amount
        };

        // Record the update
        result.relationship_updates.push(RelationshipValenceUpdate {
            from_entity_id: source_entity_id,
            to_entity_id: valence.target,
            relationship_type: relationship_type.clone(),
            attribute: attribute.clone(),
            previous_value: current_value,
            new_value,
            change_amount,
            valence_type: valence.valence_type.clone(),
        });

        debug!("Relational valence update: {} -> {} {} {} -> {} (change: {})",
            source_entity_id, valence.target, relationship_type, attribute, new_value, change_amount);

        Ok(())
    }

    /// Get the component type name for a given valence type
    fn get_component_type_for_valence(&self, valence_type: &ValenceType) -> String {
        match valence_type {
            ValenceType::Health => "Health".to_string(),
            ValenceType::Power => "Power".to_string(),
            ValenceType::Knowledge => "Knowledge".to_string(),
            ValenceType::Wealth => "Wealth".to_string(),
            ValenceType::Reputation => "Reputation".to_string(),
            _ => "Attributes".to_string(), // Generic attributes component
        }
    }

    /// Get the relationship type name for a given valence type
    fn get_relationship_type_for_valence(&self, valence_type: &ValenceType) -> String {
        match valence_type {
            ValenceType::Trust => "trust".to_string(),
            ValenceType::Affection => "affection".to_string(),
            ValenceType::Respect => "respect".to_string(),
            ValenceType::Fear => "fear".to_string(),
            ValenceType::Custom(name) => name.to_lowercase(),
            _ => "social".to_string(), // Generic social relationship
        }
    }

    /// Get the attribute name within a component/relationship for a valence type
    fn get_attribute_name_for_valence(&self, valence_type: &ValenceType) -> String {
        match valence_type {
            ValenceType::Trust => "trust".to_string(),
            ValenceType::Affection => "affection".to_string(),
            ValenceType::Respect => "respect".to_string(),
            ValenceType::Fear => "fear".to_string(),
            ValenceType::Health => "current".to_string(),
            ValenceType::Power => "level".to_string(),
            ValenceType::Knowledge => "level".to_string(),
            ValenceType::Wealth => "amount".to_string(),
            ValenceType::Reputation => "score".to_string(),
            ValenceType::Custom(name) => name.to_lowercase(),
        }
    }

    /// Get the current value of a component attribute
    async fn get_current_component_value(
        &self,
        entity_id: Uuid,
        component_type: &str,
        attribute: &str,
    ) -> Result<f32, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let component_opt = conn.interact({
            let entity_id = entity_id;
            let component_type = component_type.to_string();
            move |conn| {
                ecs_components::table
                    .filter(ecs_components::entity_id.eq(entity_id))
                    .filter(ecs_components::component_type.eq(component_type))
                    .select(EcsComponent::as_select())
                    .first::<EcsComponent>(conn)
                    .optional()
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        let value = match component_opt {
            Some(component) => {
                // Extract the attribute value from the JSONB data
                if let Some(value) = component.component_data.get(attribute) {
                    value.as_f64().map(|v| v as f32).unwrap_or(0.0)
                } else {
                    0.0 // Default value if attribute doesn't exist
                }
            }
            None => 0.0 // Default value if component doesn't exist
        };
        
        Ok(value)
    }

    /// Get the current value of a relationship attribute
    async fn get_current_relationship_value(
        &self,
        from_entity_id: Uuid,
        to_entity_id: Uuid,
        relationship_type: &str,
        attribute: &str,
    ) -> Result<f32, AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        let relationship_opt = conn.interact({
            let from_entity_id = from_entity_id;
            let to_entity_id = to_entity_id;
            let relationship_type = relationship_type.to_string();
            move |conn| {
                ecs_entity_relationships::table
                    .filter(ecs_entity_relationships::from_entity_id.eq(from_entity_id))
                    .filter(ecs_entity_relationships::to_entity_id.eq(to_entity_id))
                    .filter(ecs_entity_relationships::relationship_type.eq(relationship_type))
                    .select(EcsEntityRelationship::as_select())
                    .first::<EcsEntityRelationship>(conn)
                    .optional()
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        let value = match relationship_opt {
            Some(relationship) => {
                // Extract the attribute value from the JSONB data
                if let Some(value) = relationship.relationship_data.get(attribute) {
                    value.as_f64().map(|v| v as f32).unwrap_or(0.0)
                } else {
                    0.0 // Default value if attribute doesn't exist
                }
            }
            None => 0.0 // Default value if relationship doesn't exist
        };
        
        Ok(value)
    }

    /// Persist all valence changes to the database
    async fn persist_valence_changes(&self, result: &ValenceProcessingResult, user_id: Uuid) -> Result<(), AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // Persist component updates
        for update in &result.component_updates {
            // Get existing component data to merge with
            let existing_component = conn.interact({
                let entity_id = update.entity_id;
                let component_type = update.component_type.clone();
                move |conn| {
                    ecs_components::table
                        .filter(ecs_components::entity_id.eq(entity_id))
                        .filter(ecs_components::component_type.eq(component_type))
                        .select(EcsComponent::as_select())
                        .first::<EcsComponent>(conn)
                        .optional()
                }
            }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // Merge the new value with existing component data
            let component_data = if let Some(existing) = existing_component {
                let mut merged_data = existing.component_data.clone();
                merged_data[&update.attribute] = json!(update.new_value);
                merged_data["last_modified"] = json!(Utc::now().to_rfc3339());
                merged_data
            } else {
                // No existing component, create new data
                json!({
                    update.attribute.clone(): update.new_value,
                    "last_modified": Utc::now().to_rfc3339()
                })
            };

            // Try to update existing component first
            let rows_updated = conn.interact({
                let entity_id = update.entity_id;
                let component_type = update.component_type.clone();
                let component_data = component_data.clone();
                move |conn| {
                    diesel::update(ecs_components::table
                        .filter(ecs_components::entity_id.eq(entity_id))
                        .filter(ecs_components::component_type.eq(component_type)))
                        .set(ecs_components::component_data.eq(component_data))
                        .execute(conn)
                }
            }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // If no rows were updated, create a new component
            if rows_updated == 0 {
                let new_component = NewEcsComponent {
                    id: Uuid::new_v4(),
                    entity_id: update.entity_id,
                    user_id,
                    component_type: update.component_type.clone(),
                    component_data,
                };

                conn.interact({
                    let new_component = new_component;
                    move |conn| {
                        diesel::insert_into(ecs_components::table)
                            .values(&new_component)
                            .execute(conn)
                    }
                }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            }
        }

        // Persist relationship updates
        for update in &result.relationship_updates {
            // Create or update the relationship with the new value
            let relationship_data = json!({
                update.attribute.clone(): update.new_value,
                "last_modified": Utc::now().to_rfc3339()
            });

            // Try to update existing relationship first
            let rows_updated = conn.interact({
                let from_entity_id = update.from_entity_id;
                let to_entity_id = update.to_entity_id;
                let relationship_type = update.relationship_type.clone();
                let relationship_data = relationship_data.clone();
                move |conn| {
                    diesel::update(ecs_entity_relationships::table
                        .filter(ecs_entity_relationships::from_entity_id.eq(from_entity_id))
                        .filter(ecs_entity_relationships::to_entity_id.eq(to_entity_id))
                        .filter(ecs_entity_relationships::relationship_type.eq(relationship_type)))
                        .set(ecs_entity_relationships::relationship_data.eq(relationship_data))
                        .execute(conn)
                }
            }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // If no rows were updated, create a new relationship
            if rows_updated == 0 {
                let new_relationship = NewEcsEntityRelationship {
                    id: Uuid::new_v4(),
                    from_entity_id: update.from_entity_id,
                    to_entity_id: update.to_entity_id,
                    user_id,
                    relationship_type: update.relationship_type.clone(),
                    relationship_data,
                };

                conn.interact({
                    let new_relationship = new_relationship;
                    move |conn| {
                        diesel::insert_into(ecs_entity_relationships::table)
                            .values(&new_relationship)
                            .execute(conn)
                    }
                }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
            }
        }

        Ok(())
    }
}

/// Determines whether a valence type affects individual entities or relationships
#[derive(Debug, Clone, PartialEq)]
enum ValenceScope {
    /// Affects individual entity attributes (e.g., health, reputation)
    Individual,
    /// Affects relationships between entities (e.g., trust, affection)
    Relational,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_mock_processor() -> EventValenceProcessor {
        // Create a minimal mock processor for unit tests that don't need real DB access
        let config = ValenceProcessingConfig::default();
        // Create a dummy pool for testing - we won't actually use it in these unit tests
        let manager = deadpool_diesel::postgres::Manager::new("postgresql://test", deadpool_diesel::Runtime::Tokio1);
        let pool = deadpool_diesel::postgres::Pool::builder(manager).build().unwrap();
        EventValenceProcessor {
            db_pool: Arc::new(pool),
            config,
        }
    }

    #[test]
    fn test_valence_scope_determination() {
        let processor = create_mock_processor();

        assert_eq!(processor.determine_valence_scope(&ValenceType::Trust), ValenceScope::Relational);
        assert_eq!(processor.determine_valence_scope(&ValenceType::Health), ValenceScope::Individual);
        assert_eq!(processor.determine_valence_scope(&ValenceType::Reputation), ValenceScope::Individual);
        assert_eq!(processor.determine_valence_scope(&ValenceType::Affection), ValenceScope::Relational);
    }

    #[test]
    fn test_component_type_mapping() {
        let processor = create_mock_processor();

        assert_eq!(processor.get_component_type_for_valence(&ValenceType::Health), "Health");
        assert_eq!(processor.get_component_type_for_valence(&ValenceType::Power), "Power");
        assert_eq!(processor.get_component_type_for_valence(&ValenceType::Trust), "Attributes");
    }

    #[test]
    fn test_relationship_type_mapping() {
        let processor = create_mock_processor();

        assert_eq!(processor.get_relationship_type_for_valence(&ValenceType::Trust), "trust");
        assert_eq!(processor.get_relationship_type_for_valence(&ValenceType::Affection), "affection");
        assert_eq!(processor.get_relationship_type_for_valence(&ValenceType::Custom("friendship".to_string())), "friendship");
    }
}