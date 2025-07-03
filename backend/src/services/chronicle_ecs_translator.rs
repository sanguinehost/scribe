// backend/src/services/chronicle_ecs_translator.rs
//
// Chronicle-to-ECS Translation Service
// 
// This service translates chronicle events into ECS entity state changes,
// implementing the bridge between narrative events and structured game state.

use std::sync::Arc;
use uuid::Uuid;
use serde_json::{Value as JsonValue, json};
use tracing::{info, warn, debug, error, instrument};

use crate::{
    PgPool,
    errors::AppError,
    models::{
        chronicle_event::ChronicleEvent,
        narrative_ontology::{EventActor, ActorRole, EventValence, ValenceType, NarrativeAction},
        ecs::{Component, HealthComponent, PositionComponent, RelationshipsComponent},
        ecs_diesel::{EcsEntity, NewEcsEntity, NewEcsComponent, NewEcsEntityRelationship},
    },
    schema::{ecs_entities, ecs_components, ecs_entity_relationships},
};

use diesel::prelude::*;
use chrono::Utc;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Hash user ID for privacy-preserving logging (GDPR/privacy compliant)
fn hash_user_id(user_id: Uuid) -> u64 {
    let mut hasher = DefaultHasher::new();
    user_id.hash(&mut hasher);
    hasher.finish()
}

/// Result of translating a chronicle event to ECS changes
#[derive(Debug, Clone)]
pub struct TranslationResult {
    /// IDs of entities that were created during translation
    pub entities_created: Vec<Uuid>,
    /// Component updates that were applied
    pub component_updates: Vec<ComponentUpdate>,
    /// Relationship updates that were applied
    pub relationship_updates: Vec<RelationshipUpdate>,
    /// Any errors or warnings encountered during translation
    pub messages: Vec<String>,
}

/// Represents a component update
#[derive(Debug, Clone)]
pub struct ComponentUpdate {
    pub entity_id: Uuid,
    pub component_type: String,
    pub component_data: JsonValue,
    pub operation: ComponentOperation,
}

/// Type of component operation
#[derive(Debug, Clone)]
pub enum ComponentOperation {
    Create,
    Update,
    Delete,
}

/// Represents a relationship update
#[derive(Debug, Clone)]
pub struct RelationshipUpdate {
    pub from_entity_id: Uuid,
    pub to_entity_id: Uuid,
    pub relationship_type: String,
    pub relationship_data: JsonValue,
    pub operation: RelationshipOperation,
}

/// Type of relationship operation
#[derive(Debug, Clone)]
pub enum RelationshipOperation {
    Create,
    Update,
    Delete,
}

/// Service for translating chronicle events to ECS state changes
pub struct ChronicleEcsTranslator {
    db_pool: Arc<PgPool>,
}

impl ChronicleEcsTranslator {
    /// Create a new translator service
    pub fn new(db_pool: Arc<PgPool>) -> Self {
        Self { db_pool }
    }

    /// Translate a chronicle event into ECS state changes
    #[instrument(skip(self, event), fields(event_id = %event.id, event_type = %event.event_type, user_hash = %format!("{:x}", hash_user_id(user_id))))]
    pub async fn translate_event(&self, event: &ChronicleEvent, user_id: Uuid) -> Result<TranslationResult, AppError> {
        debug!("Starting translation of chronicle event");
        
        let mut result = TranslationResult {
            entities_created: Vec::new(),
            component_updates: Vec::new(),
            relationship_updates: Vec::new(),
            messages: Vec::new(),
        };

        // Parse actors from the event
        let actors = match event.get_actors() {
            Ok(actors) => actors,
            Err(e) => {
                warn!("Failed to parse actors from event: {}", e);
                result.messages.push(format!("Failed to parse actors: {}", e));
                return Ok(result);
            }
        };

        // Parse action from the event
        let action = event.get_action();

        // Parse valence changes from the event
        let valence_changes = match event.get_valence() {
            Ok(changes) => changes,
            Err(e) => {
                debug!("No valence changes in event or parse error: {}", e);
                Vec::new()
            }
        };

        // Step 1: Ensure all actor entities exist in ECS
        self.ensure_entities_exist(&actors, user_id, &mut result).await?;

        // Step 2: Apply action-based state changes
        if let Some(action) = action {
            self.apply_action_changes(&action, &actors, user_id, event, &mut result).await?;
        }

        // Step 3: Apply valence changes to relationships
        if !valence_changes.is_empty() {
            self.apply_valence_changes(&valence_changes, &actors, user_id, &mut result).await?;
        }

        // Step 4: Persist all changes to database
        self.persist_changes(&result, user_id).await?;

        info!("Translation completed: {} entities created, {} component updates, {} relationship updates",
            result.entities_created.len(), result.component_updates.len(), result.relationship_updates.len());

        Ok(result)
    }

    /// Ensure all actor entities exist in the ECS, creating them if necessary
    async fn ensure_entities_exist(&self, actors: &[EventActor], user_id: Uuid, result: &mut TranslationResult) -> Result<(), AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        for actor in actors {
            // Check if entity already exists for this user
            let exists = conn.interact({
                let entity_id = actor.entity_id;
                move |conn| {
                    ecs_entities::table
                        .filter(ecs_entities::id.eq(entity_id))
                        .filter(ecs_entities::user_id.eq(user_id))
                        .select(EcsEntity::as_select())
                        .first::<EcsEntity>(conn)
                        .optional()
                }
            }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            if exists.is_none() {
                // Create new entity with basic archetype
                let archetype = self.determine_entity_archetype(actor);
                
                let new_entity = NewEcsEntity {
                    id: actor.entity_id,
                    user_id,
                    archetype_signature: archetype,
                };

                conn.interact({
                    let new_entity = new_entity;
                    move |conn| {
                        diesel::insert_into(ecs_entities::table)
                            .values(&new_entity)
                            .on_conflict(ecs_entities::id)
                            .do_nothing()
                            .execute(conn)
                    }
                }).await.map_err(|e| {
                    error!("Failed to insert entity - DB interaction error: {}", e);
                    AppError::DbInteractError(e.to_string())
                })?
                .map_err(|e| {
                    error!("Failed to insert entity - Database query error: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

                result.entities_created.push(actor.entity_id);
                
                // Create basic components for new entities
                self.create_basic_components(actor, user_id, result).await?;
            }
        }

        Ok(())
    }

    /// Determine the archetype signature for a new entity based on its actor role and context
    fn determine_entity_archetype(&self, actor: &EventActor) -> String {
        // Default archetype for most entities
        let mut components = vec!["Position"];

        // Add components based on context clues
        if let Some(context) = &actor.context {
            let context_lower = context.to_lowercase();
            
            // Characters/people get health and relationships
            if context_lower.contains("character") || 
               context_lower.contains("person") || 
               context_lower.contains("adventurer") ||
               context_lower.contains("hero") ||
               context_lower.contains("merchant") {
                components.extend_from_slice(&["Health", "Relationships"]);
            }
            
            // Items get inventory properties
            if context_lower.contains("item") || 
               context_lower.contains("weapon") || 
               context_lower.contains("sword") ||
               context_lower.contains("potion") ||
               context_lower.contains("artifact") {
                // Items don't need health, but might be in inventories
                // Keep just Position for now
            }
        }

        // Default to character-like entity if uncertain
        if components.len() == 1 {
            components.extend_from_slice(&["Health", "Relationships"]);
        }

        components.join("|")
    }

    /// Create basic components for a newly created entity
    async fn create_basic_components(&self, actor: &EventActor, user_id: Uuid, result: &mut TranslationResult) -> Result<(), AppError> {
        let archetype = self.determine_entity_archetype(actor);
        let component_types: Vec<&str> = archetype.split('|').collect();

        for component_type in component_types {
            let component_data = match component_type {
                "Health" => {
                    let health = HealthComponent {
                        current: 100,
                        max: 100,
                        regeneration_rate: 1.0,
                    };
                    health.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?
                }
                "Position" => {
                    let position = PositionComponent {
                        x: 0.0,
                        y: 0.0,
                        z: 0.0,
                        zone: "unknown".to_string(),
                    };
                    position.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?
                }
                "Relationships" => {
                    let relationships = RelationshipsComponent {
                        relationships: Vec::new(),
                    };
                    relationships.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?
                }
                _ => {
                    // Unknown component type, skip
                    continue;
                }
            };

            result.component_updates.push(ComponentUpdate {
                entity_id: actor.entity_id,
                component_type: component_type.to_string(),
                component_data,
                operation: ComponentOperation::Create,
            });
        }

        Ok(())
    }

    /// Apply action-based state changes to entities
    async fn apply_action_changes(
        &self,
        action: &NarrativeAction,
        actors: &[EventActor],
        user_id: Uuid,
        event: &ChronicleEvent,
        result: &mut TranslationResult,
    ) -> Result<(), AppError> {
        match action {
            NarrativeAction::Met => {
                self.handle_meeting_action(actors, result).await?;
            }
            NarrativeAction::Acquired | NarrativeAction::Found | NarrativeAction::Discovered => {
                self.handle_acquisition_action(actors, event, result).await?;
            }
            NarrativeAction::Attacked | NarrativeAction::Defended => {
                self.handle_combat_action(actors, result).await?;
            }
            NarrativeAction::Betrayed => {
                self.handle_betrayal_action(actors, result).await?;
            }
            // Note: Helped is not in NarrativeAction enum yet
            // NarrativeAction::Helped => {
            //     self.handle_help_action(actors, result).await?;
            // }
            _ => {
                debug!("No specific handler for action: {:?}", action);
            }
        }

        Ok(())
    }

    /// Handle meeting actions - create mutual relationships
    async fn handle_meeting_action(&self, actors: &[EventActor], result: &mut TranslationResult) -> Result<(), AppError> {
        // Find agent and patient actors
        let agents: Vec<_> = actors.iter().filter(|a| a.role == ActorRole::Agent).collect();
        let patients: Vec<_> = actors.iter().filter(|a| a.role == ActorRole::Patient).collect();

        // Create mutual acquaintance relationships
        for agent in &agents {
            for patient in &patients {
                if agent.entity_id != patient.entity_id {
                    // Create bidirectional "knows" relationship
                    result.relationship_updates.push(RelationshipUpdate {
                        from_entity_id: agent.entity_id,
                        to_entity_id: patient.entity_id,
                        relationship_type: "knows".to_string(),
                        relationship_data: json!({
                            "trust": 0.1,
                            "affection": 0.0,
                            "created_at": Utc::now().to_rfc3339(),
                            "context": "first meeting"
                        }),
                        operation: RelationshipOperation::Create,
                    });

                    result.relationship_updates.push(RelationshipUpdate {
                        from_entity_id: patient.entity_id,
                        to_entity_id: agent.entity_id,
                        relationship_type: "knows".to_string(),
                        relationship_data: json!({
                            "trust": 0.1,
                            "affection": 0.0,
                            "created_at": Utc::now().to_rfc3339(),
                            "context": "first meeting"
                        }),
                        operation: RelationshipOperation::Create,
                    });
                }
            }
        }

        Ok(())
    }

    /// Handle acquisition actions - update inventory components
    async fn handle_acquisition_action(&self, actors: &[EventActor], event: &ChronicleEvent, result: &mut TranslationResult) -> Result<(), AppError> {
        // Find agent (acquirer) and patient (item being acquired)
        let agent = actors.iter().find(|a| a.role == ActorRole::Agent);
        let patient = actors.iter().find(|a| a.role == ActorRole::Patient);

        if let (Some(acquirer), Some(item)) = (agent, patient) {
            // Update acquirer's inventory
            result.component_updates.push(ComponentUpdate {
                entity_id: acquirer.entity_id,
                component_type: "Inventory".to_string(),
                component_data: json!({
                    "operation": "add_item",
                    "item_id": item.entity_id,
                    "quantity": 1,
                    "context": event.summary
                }),
                operation: ComponentOperation::Update,
            });
        }

        Ok(())
    }

    /// Handle combat actions - update health components
    async fn handle_combat_action(&self, actors: &[EventActor], result: &mut TranslationResult) -> Result<(), AppError> {
        // In combat, patient typically takes damage
        let patients: Vec<_> = actors.iter().filter(|a| a.role == ActorRole::Patient).collect();

        for patient in patients {
            result.component_updates.push(ComponentUpdate {
                entity_id: patient.entity_id,
                component_type: "Health".to_string(),
                component_data: json!({
                    "operation": "damage",
                    "amount": 10.0,
                    "reason": "combat"
                }),
                operation: ComponentOperation::Update,
            });
        }

        Ok(())
    }

    /// Handle betrayal actions - damage trust relationships
    async fn handle_betrayal_action(&self, actors: &[EventActor], result: &mut TranslationResult) -> Result<(), AppError> {
        let agent = actors.iter().find(|a| a.role == ActorRole::Agent);
        let patient = actors.iter().find(|a| a.role == ActorRole::Patient);

        if let (Some(betrayer), Some(betrayed)) = (agent, patient) {
            // Damage trust from betrayed to betrayer
            result.relationship_updates.push(RelationshipUpdate {
                from_entity_id: betrayed.entity_id,
                to_entity_id: betrayer.entity_id,
                relationship_type: "trust".to_string(),
                relationship_data: json!({
                    "change": -0.8,
                    "reason": "betrayal"
                }),
                operation: RelationshipOperation::Update,
            });
        }

        Ok(())
    }

    /// Handle help actions - improve trust relationships
    async fn handle_help_action(&self, actors: &[EventActor], result: &mut TranslationResult) -> Result<(), AppError> {
        let agent = actors.iter().find(|a| a.role == ActorRole::Agent);
        let beneficiary = actors.iter().find(|a| a.role == ActorRole::Beneficiary);

        if let (Some(helper), Some(helped)) = (agent, beneficiary) {
            // Increase trust from helped to helper
            result.relationship_updates.push(RelationshipUpdate {
                from_entity_id: helped.entity_id,
                to_entity_id: helper.entity_id,
                relationship_type: "trust".to_string(),
                relationship_data: json!({
                    "change": 0.3,
                    "reason": "received help"
                }),
                operation: RelationshipOperation::Update,
            });
        }

        Ok(())
    }

    /// Apply valence changes to relationship components
    async fn apply_valence_changes(
        &self,
        valence_changes: &[EventValence],
        actors: &[EventActor],
        user_id: Uuid,
        result: &mut TranslationResult,
    ) -> Result<(), AppError> {
        for valence in valence_changes {
            let relationship_type = match valence.valence_type {
                ValenceType::Trust => "trust",
                ValenceType::Affection => "affection",
                ValenceType::Respect => "respect",
                ValenceType::Fear => "fear",
                ValenceType::Reputation => "reputation",
                _ => "unknown",
            };

            // Find the source entity (usually the agent in the actors list)
            let source_entity = actors.iter()
                .find(|a| a.role == ActorRole::Agent)
                .map(|a| a.entity_id)
                .unwrap_or_else(|| {
                    // Fallback: use the first entity that's not the target
                    actors.iter()
                        .find(|a| a.entity_id != valence.target)
                        .map(|a| a.entity_id)
                        .unwrap_or(valence.target) // Last resort: use target itself
                });

            result.relationship_updates.push(RelationshipUpdate {
                from_entity_id: source_entity,
                to_entity_id: valence.target,
                relationship_type: relationship_type.to_string(),
                relationship_data: json!({
                    "change": valence.change,
                    "description": valence.description
                }),
                operation: RelationshipOperation::Update,
            });
        }

        Ok(())
    }

    /// Persist all changes to the database
    async fn persist_changes(&self, result: &TranslationResult, user_id: Uuid) -> Result<(), AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // Persist component updates
        for update in &result.component_updates {
            if matches!(update.operation, ComponentOperation::Create) {
                let new_component = NewEcsComponent {
                    id: Uuid::new_v4(),
                    entity_id: update.entity_id,
                    user_id,
                    component_type: update.component_type.clone(),
                    component_data: update.component_data.clone(),
                };

                conn.interact({
                    let new_component = new_component;
                    move |conn| {
                        diesel::insert_into(ecs_components::table)
                            .values(&new_component)
                            .on_conflict((ecs_components::entity_id, ecs_components::component_type))
                            .do_nothing()
                            .execute(conn)
                    }
                }).await.map_err(|e| {
                    error!("Failed to insert component - DB interaction error: {}", e);
                    AppError::DbInteractError(e.to_string())
                })?
                .map_err(|e| {
                    error!("Failed to insert component (entity_id: {}, type: {}) - Database query error: {}", 
                           update.entity_id, update.component_type, e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;
            }
        }

        // Persist relationship updates
        for update in &result.relationship_updates {
            if matches!(update.operation, RelationshipOperation::Create) {
                let new_relationship = NewEcsEntityRelationship {
                    id: Uuid::new_v4(),
                    from_entity_id: update.from_entity_id,
                    to_entity_id: update.to_entity_id,
                    user_id,
                    relationship_type: update.relationship_type.clone(),
                    relationship_data: update.relationship_data.clone(),
                };

                conn.interact({
                    let new_relationship = new_relationship;
                    move |conn| {
                        diesel::insert_into(ecs_entity_relationships::table)
                            .values(&new_relationship)
                            .on_conflict((
                                ecs_entity_relationships::from_entity_id,
                                ecs_entity_relationships::to_entity_id,
                                ecs_entity_relationships::relationship_type
                            ))
                            .do_nothing()
                            .execute(conn)
                    }
                }).await.map_err(|e| {
                    error!("Failed to insert relationship - DB interaction error: {}", e);
                    AppError::DbInteractError(e.to_string())
                })?
                .map_err(|e| {
                    error!("Failed to insert relationship (from: {}, to: {}, type: {}) - Database query error: {}", 
                           update.from_entity_id, update.to_entity_id, update.relationship_type, e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;
            }
        }

        Ok(())
    }
}