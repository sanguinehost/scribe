// backend/src/services/chronicle_ecs_translator.rs
//
// Chronicle-to-ECS Translation Service
// 
// This service translates chronicle events into ECS entity state changes,
// implementing the bridge between narrative events and structured game state.

use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use serde_json::{Value as JsonValue, json};
use tracing::{info, warn, debug, error, instrument};

use crate::{
    PgPool,
    errors::AppError,
    models::{
        chronicle_event::ChronicleEvent,
        narrative_ontology::{EventActor, ActorRole, EventValence, ValenceType, NarrativeAction},
        ecs::{Component, HealthComponent, PositionComponent, RelationshipsComponent, NameComponent, InventoryComponent},
        ecs_diesel::{EcsEntity, NewEcsEntity, NewEcsComponent, NewEcsEntityRelationship},
    },
    schema::{ecs_entities, ecs_components, ecs_entity_relationships},
    services::agentic::entity_resolution_tool::NarrativeContext,
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

/// Full entity data extracted from event JSON
#[derive(Debug, Clone)]
struct EntityData {
    name: String,
    entity_type: String,
    confidence: f64,
    _is_new: bool, // TODO: Track if entity is newly created for lifecycle management
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
        debug!("Event actors field: {:?}", event.actors);
        
        let mut result = TranslationResult {
            entities_created: Vec::new(),
            component_updates: Vec::new(),
            relationship_updates: Vec::new(),
            messages: Vec::new(),
        };

        // Parse actors from the event with fallback for missing entity_id
        let actors = match event.get_actors_with_fallback() {
            Ok(actors) => {
                debug!("Parsed {} actors from event", actors.len());
                if actors.is_empty() {
                    warn!(
                        "EMPTY ACTORS DETECTED - Event ID: {}, Type: {}, Action: {:?}, Summary: {}, User: {:#x}", 
                        event.id, 
                        event.event_type,
                        event.get_action(),
                        event.summary.chars().take(100).collect::<String>(),
                        hash_user_id(user_id)
                    );
                    debug!("Event data for empty actors analysis: {}", 
                        serde_json::to_string_pretty(&event.event_data).unwrap_or_else(|_| "Failed to serialize".to_string())
                    );
                    result.messages.push("Warning: No actors found in event - this may indicate incomplete entity extraction".to_string());
                } else {
                    for (i, actor) in actors.iter().enumerate() {
                        debug!("Actor {}: role={:?}, entity_id={}, context={:?}", 
                            i, actor.role, actor.entity_id, actor.context);
                    }
                }
                actors
            },
            Err(e) => {
                warn!("Failed to parse actors from event: {}", e);
                result.messages.push(format!("Failed to parse actors: {}", e));
                return Ok(result);
            }
        };

        // Parse action from the event
        let action = event.get_action();
        debug!("Event action: {:?}", action);

        // Parse valence changes from the event
        let valence_changes = match event.get_valence() {
            Ok(changes) => {
                debug!("Event valence changes: {} entries", changes.len());
                changes
            },
            Err(e) => {
                debug!("No valence changes in event or parse error: {}", e);
                Vec::new()
            }
        };

        // Step 1: Ensure all actor entities exist in ECS
        let entity_data_map = self.extract_entity_data_from_event(event);
        debug!("Extracted entity data for {} entities: {:?}", entity_data_map.len(), entity_data_map);
        self.ensure_entities_exist(&actors, user_id, event, &mut result, &entity_data_map).await?;

        // Step 2: Apply action-based state changes
        if let Some(action) = action {
            self.apply_action_changes(&action, &actors, user_id, event, &mut result, &entity_data_map).await?;
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

    /// Enhanced translation with causal tracking
    /// 
    /// This method extends the base translation with causal relationship tracking
    /// as specified in the incremental enhancement plan.
    #[instrument(skip(self, event, previous_event), fields(event_id = %event.id, event_type = %event.event_type, user_hash = %format!("{:x}", hash_user_id(user_id))))]
    pub async fn translate_event_with_causality(
        &self, 
        event: &ChronicleEvent, 
        user_id: Uuid,
        previous_event: Option<&ChronicleEvent>,
    ) -> Result<TranslationResult, AppError> {
        debug!("Starting enhanced translation with causal tracking");
        
        // Start with standard translation
        let mut result = self.translate_event(event, user_id).await?;
        
        // Track causality if there's a previous event
        if let Some(prev) = previous_event {
            info!("Tracking causal relationship from event {} to {}", prev.id, event.id);
            
            // Parse actors from both events
            let current_actors = event.get_actors().unwrap_or_default();
            
            // Update chronicle event causality in database
            self.update_event_causality(event.id, prev.id).await?;
            
            // Create causal relationships between entities
            self.create_causal_relationships(event, &current_actors, &mut result)?;
            
            // Persist the new causal relationships to database
            self.persist_causal_relationships(&result.relationship_updates, user_id).await?;
            
            result.messages.push(format!("Added causal tracking from event {} to {}", prev.id, event.id));
        }
        
        Ok(result)
    }

    /// Update chronicle event causality fields in the database
    async fn update_event_causality(&self, event_id: Uuid, caused_by_event_id: Uuid) -> Result<(), AppError> {
        use crate::schema::chronicle_events;
        
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
            
        // Update the current event to reference the causing event
        conn.interact({
            let event_id = event_id;
            let caused_by_event_id = caused_by_event_id;
            move |conn| {
                diesel::update(chronicle_events::table.filter(chronicle_events::id.eq(event_id)))
                    .set(chronicle_events::caused_by_event_id.eq(Some(caused_by_event_id)))
                    .execute(conn)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
          .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        
        // Update the previous event to add this event to its causes array
        conn.interact({
            let event_id = event_id;
            let caused_by_event_id = caused_by_event_id;
            move |conn| {
                // First get the current causes_event_ids
                let current_causes: Option<Vec<Option<Uuid>>> = chronicle_events::table
                    .filter(chronicle_events::id.eq(caused_by_event_id))
                    .select(chronicle_events::causes_event_ids)
                    .first::<Option<Vec<Option<Uuid>>>>(conn)
                    .optional()?
                    .flatten();
                
                // Add the new event to the causes array
                let mut updated_causes = current_causes.unwrap_or_default();
                updated_causes.push(Some(event_id));
                
                // Update the causing event
                diesel::update(chronicle_events::table.filter(chronicle_events::id.eq(caused_by_event_id)))
                    .set(chronicle_events::causes_event_ids.eq(Some(updated_causes)))
                    .execute(conn)
            }
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
          .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        
        debug!("Updated causal chain: event {} caused by event {}", event_id, caused_by_event_id);
        Ok(())
    }

    /// Ensure all actor entities exist in the ECS, creating them if necessary
    async fn ensure_entities_exist(&self, actors: &[EventActor], user_id: Uuid, event: &ChronicleEvent, result: &mut TranslationResult, entity_data_map: &HashMap<Uuid, EntityData>) -> Result<(), AppError> {
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
                // Create new entity with archetype based on extracted data
                let entity_data = entity_data_map.get(&actor.entity_id);
                let archetype = self.determine_entity_archetype_from_data(entity_data);
                
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
                let entity_data = entity_data_map.get(&actor.entity_id);
                self.create_basic_components(actor, user_id, event, result, entity_data).await?;
            }
        }

        Ok(())
    }

    /// Extract full entity data from the original event JSON before EventActor parsing
    fn extract_entity_data_from_event(&self, event: &ChronicleEvent) -> HashMap<Uuid, EntityData> {
        let mut entity_data_map = HashMap::new();
        
        // First try to get resolved actors from event_data.actors (contains full resolution data)
        if let Some(event_data) = &event.event_data {
            if let Some(actors_json) = event_data.get("actors") {
                if let Some(actors_array) = actors_json.as_array() {
                    for actor_value in actors_array {
                        if let Some(entity_id_str) = actor_value.get("entity_id").and_then(|v| v.as_str()) {
                            if let Ok(entity_id) = Uuid::parse_str(entity_id_str) {
                                let entity_data = EntityData {
                                    name: actor_value.get("entity_name").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                                    entity_type: actor_value.get("entity_type").and_then(|v| v.as_str()).unwrap_or("UNKNOWN").to_string(),
                                    confidence: actor_value.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.5),
                                    _is_new: actor_value.get("is_new").and_then(|v| v.as_bool()).unwrap_or(true),
                                };
                                entity_data_map.insert(entity_id, entity_data);
                            }
                        }
                    }
                    return entity_data_map; // Return early if we found resolved actors
                }
            }
        }
        
        // Fallback to legacy actors field if no resolved actors found
        if let Some(actors_json) = &event.actors {
            if let Some(actors_array) = actors_json.as_array() {
                for actor_value in actors_array {
                    if let Some(entity_id_str) = actor_value.get("entity_id").and_then(|v| v.as_str()) {
                        if let Ok(entity_id) = Uuid::parse_str(entity_id_str) {
                            let entity_data = EntityData {
                                name: actor_value.get("entity_name").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                                entity_type: actor_value.get("entity_type").and_then(|v| v.as_str()).unwrap_or("UNKNOWN").to_string(),
                                confidence: actor_value.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.5),
                                _is_new: actor_value.get("is_new").and_then(|v| v.as_bool()).unwrap_or(true),
                            };
                            entity_data_map.insert(entity_id, entity_data);
                        }
                    }
                }
            }
        }
        
        entity_data_map
    }

    /// Determine the archetype signature for a new entity based on extracted entity data
    fn determine_entity_archetype_from_data(&self, entity_data: Option<&EntityData>) -> String {
        let mut components = vec!["Name"]; // Always start with Name
        
        match entity_data {
            Some(data) => {
                match data.entity_type.as_str() {
                    "CHARACTER" => {
                        components.extend_from_slice(&["Position", "Health", "Relationships", "Personality", "Skills", "Inventory"]);
                    },
                    "LOCATION" => {
                        components.extend_from_slice(&["Position", "Spatial_Containment", "Description", "Environmental_Properties"]);
                    },
                    "ITEM" => {
                        components.extend_from_slice(&["Position", "Physical_Properties", "Ownership", "Item_State"]);
                    },
                    "CONCEPT" => {
                        components.extend_from_slice(&["Abstract_Properties", "Conceptual_Relationships"]);
                    },
                    "ORGANIZATION" => {
                        components.extend_from_slice(&["Position", "Description", "Organizational_Structure", "Relationships", "Operational_Status"]);
                    },
                    _ => {
                        // Unknown type - default to basic entity
                        components.extend_from_slice(&["Position", "Description"]);
                    }
                }
            },
            None => {
                // No entity data - fallback to basic character-like entity
                components.extend_from_slice(&["Position", "Health", "Relationships"]);
            }
        }

        components.join("|")
    }

    /// Create basic components for a newly created entity
    async fn create_basic_components(&self, actor: &EventActor, user_id: Uuid, event: &ChronicleEvent, result: &mut TranslationResult, entity_data: Option<&EntityData>) -> Result<(), AppError> {
        let archetype = self.determine_entity_archetype_from_data(entity_data);
        let component_types: Vec<&str> = archetype.split('|').collect();

        // Extract narrative context from event if available
        let narrative_context = self.extract_narrative_context_from_event(event);
        
        // Always create a ChronicleSource component to link entities to their chronicles
        result.component_updates.push(ComponentUpdate {
            entity_id: actor.entity_id,
            component_type: "ChronicleSource".to_string(),
            component_data: json!({
                "chronicle_id": event.chronicle_id,
                "source_event_id": event.id,
                "created_at": Utc::now().to_rfc3339(),
                "entity_id": actor.entity_id,
                "user_id": user_id  // Associate with user for data isolation
            }),
            operation: ComponentOperation::Create,
        });

        for component_type in component_types {
            let component_data = match component_type {
                "Health" => {
                    // Use contextual health data if available, otherwise defaults
                    let health = self.create_health_component_from_context(entity_data, narrative_context.as_ref())?;
                    health.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?
                }
                "Position" => {
                    // Use spatial context to populate position
                    let position = self.create_position_component_from_context(entity_data, narrative_context.as_ref())?;
                    position.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?
                }
                "Relationships" => {
                    // This is now handled by handle_social_context, but we still need the component
                    let relationships = RelationshipsComponent { relationships: Vec::new() };
                    relationships.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?
                }
                "Name" => {
                    let actual_name = entity_data.map(|d| d.name.as_str()).unwrap_or("Unknown");
                    let name = NameComponent {
                        name: actual_name.to_string(),
                        display_name: actual_name.to_string(),
                        aliases: Vec::new(),
                    };
                    name.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?
                }
                "Inventory" => {
                    let inventory = InventoryComponent {
                        items: Vec::new(),
                        capacity: 20,
                    };
                    inventory.to_json().map_err(|e| AppError::SerializationError(e.to_string()))?
                }
                "Description" => {
                    // Use entity description from narrative context
                    self.create_description_component_from_context(entity_data, narrative_context.as_ref())?
                }
                // Enhanced components using rich context data
                "Personality" | "Skills" | "Spatial_Containment" | "Environmental_Properties" |
                "Physical_Properties" | "Ownership" | "Item_State" | "Abstract_Properties" | "Conceptual_Relationships" => {
                    // Create contextual component data using narrative context
                    self.create_contextual_component(component_type, entity_data, narrative_context.as_ref())?
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
        _user_id: Uuid,
        event: &ChronicleEvent,
        result: &mut TranslationResult,
        entity_data_map: &HashMap<Uuid, EntityData>,
    ) -> Result<(), AppError> {
        self.handle_social_context(event, result, entity_data_map).await?;

        match action {
            NarrativeAction::Met => {
                // This is now handled by handle_social_context
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

    /// Handle social context from the narrative to create relationships
    async fn handle_social_context(
        &self,
        event: &ChronicleEvent,
        result: &mut TranslationResult,
        entity_data_map: &HashMap<Uuid, EntityData>,
    ) -> Result<(), AppError> {
        if let Some(context) = self.extract_narrative_context_from_event(event) {
            let name_to_uuid_map: HashMap<_, _> = entity_data_map
                .iter()
                .map(|(uuid, data)| (data.name.as_str(), *uuid))
                .collect();

            for rel in &context.social_context.relationships {
                if let (Some(&entity1_id), Some(&entity2_id)) = (
                    name_to_uuid_map.get(rel.entity1.as_str()),
                    name_to_uuid_map.get(rel.entity2.as_str()),
                ) {
                    if entity1_id == entity2_id { continue; }

                    // Create bidirectional relationship
                    result.relationship_updates.push(RelationshipUpdate {
                        from_entity_id: entity1_id,
                        to_entity_id: entity2_id,
                        relationship_type: rel.relationship.clone(),
                        relationship_data: json!({
                            "trust": 0.1,
                            "affection": 0.0,
                            "created_at": Utc::now().to_rfc3339(),
                            "context": format!("Established from narrative: {}", event.summary.chars().take(100).collect::<String>())
                        }),
                        operation: RelationshipOperation::Create,
                    });

                    result.relationship_updates.push(RelationshipUpdate {
                        from_entity_id: entity2_id,
                        to_entity_id: entity1_id,
                        relationship_type: rel.relationship.clone(),
                        relationship_data: json!({
                            "trust": 0.1,
                            "affection": 0.0,
                            "created_at": Utc::now().to_rfc3339(),
                            "context": format!("Established from narrative: {}", event.summary.chars().take(100).collect::<String>())
                        }),
                        operation: RelationshipOperation::Create,
                    });
                } else {
                    warn!("Could not resolve entities for social relationship: {} <-> {}", rel.entity1, rel.entity2);
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
    #[allow(dead_code)] // TODO: Integrate help action handling into event translation
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

    /// Create causal relationships between entities
    /// 
    /// This method implements the enhanced causal tracking as specified
    /// in the incremental enhancement plan, creating relationships with
    /// the new graph-like metadata fields.
    fn create_causal_relationships(
        &self,
        event: &ChronicleEvent,
        actors: &[EventActor],
        result: &mut TranslationResult,
    ) -> Result<(), AppError> {
        use crate::models::ecs::RelationshipCategory;
        
        // Agent causes effect on Patient
        let agents: Vec<_> = actors.iter().filter(|a| a.role == ActorRole::Agent).collect();
        let patients: Vec<_> = actors.iter().filter(|a| a.role == ActorRole::Patient).collect();
        
        for agent in &agents {
            for patient in &patients {
                // Create enhanced causal relationship with new metadata fields
                result.relationship_updates.push(RelationshipUpdate {
                    from_entity_id: agent.entity_id,
                    to_entity_id: patient.entity_id,
                    relationship_type: "causes_effect_on".to_string(),
                    relationship_data: json!({
                        // Enhanced fields for graph-like capabilities
                        "category": RelationshipCategory::Causal.as_str(),
                        "strength": 0.7,
                        "causal_metadata": {
                            "caused_by_event": event.id,
                            "confidence": 0.8,
                            "causality_type": "direct"
                        },
                        "temporal_validity": {
                            "valid_from": event.created_at,
                            "valid_until": null,
                            "confidence": 1.0
                        },
                        // Legacy fields for backwards compatibility
                        "caused_by_event": event.id,
                        "timestamp": event.created_at,
                        "trust": 0.0,
                        "affection": 0.0
                    }),
                    operation: RelationshipOperation::Create,
                });
                
                debug!("Created causal relationship: {} causes effect on {} via event {}", 
                       agent.entity_id, patient.entity_id, event.id);
            }
        }
        
        // Also create bidirectional "affected_by" relationships for better graph traversal
        for patient in &patients {
            for agent in &agents {
                result.relationship_updates.push(RelationshipUpdate {
                    from_entity_id: patient.entity_id,
                    to_entity_id: agent.entity_id,
                    relationship_type: "affected_by".to_string(),
                    relationship_data: json!({
                        "category": RelationshipCategory::Causal.as_str(),
                        "strength": 0.6,
                        "causal_metadata": {
                            "caused_by_event": event.id,
                            "confidence": 0.8,
                            "causality_type": "direct"
                        },
                        "temporal_validity": {
                            "valid_from": event.created_at,
                            "valid_until": null,
                            "confidence": 1.0
                        },
                        "caused_by_event": event.id,
                        "timestamp": event.created_at,
                        "trust": 0.0,
                        "affection": 0.0
                    }),
                    operation: RelationshipOperation::Create,
                });
            }
        }
        
        Ok(())
    }

    /// Apply valence changes to relationship components
    async fn apply_valence_changes(
        &self,
        valence_changes: &[EventValence],
        actors: &[EventActor],
        _user_id: Uuid,
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
                // Extract enhanced relationship metadata from relationship_data
                let category = update.relationship_data.get("category")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                    
                let strength = update.relationship_data.get("strength")
                    .and_then(|v| v.as_f64());
                    
                let causal_metadata = update.relationship_data.get("causal_metadata")
                    .cloned();
                    
                let temporal_validity = update.relationship_data.get("temporal_validity")
                    .cloned();
                
                let new_relationship = NewEcsEntityRelationship {
                    id: Uuid::new_v4(),
                    from_entity_id: update.from_entity_id,
                    to_entity_id: update.to_entity_id,
                    user_id,
                    relationship_type: update.relationship_type.clone(),
                    relationship_data: update.relationship_data.clone(),
                    // Enhanced fields for graph-like capabilities
                    relationship_category: category,
                    strength,
                    causal_metadata,
                    temporal_validity,
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

    /// Persist causal relationships to the database
    async fn persist_causal_relationships(&self, relationship_updates: &[RelationshipUpdate], user_id: Uuid) -> Result<(), AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // Filter for causal relationships and persist them
        for update in relationship_updates {
            if matches!(update.operation, RelationshipOperation::Create) && 
               (update.relationship_type == "causes_effect_on" || update.relationship_type == "affected_by") {
                
                // Extract enhanced relationship metadata from relationship_data
                let category = update.relationship_data.get("category")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                    
                let strength = update.relationship_data.get("strength")
                    .and_then(|v| v.as_f64());
                    
                let causal_metadata = update.relationship_data.get("causal_metadata")
                    .cloned();
                    
                let temporal_validity = update.relationship_data.get("temporal_validity")
                    .cloned();
                
                let new_relationship = NewEcsEntityRelationship {
                    id: Uuid::new_v4(),
                    from_entity_id: update.from_entity_id,
                    to_entity_id: update.to_entity_id,
                    user_id,
                    relationship_type: update.relationship_type.clone(),
                    relationship_data: update.relationship_data.clone(),
                    // Enhanced fields for graph-like capabilities
                    relationship_category: category,
                    strength,
                    causal_metadata,
                    temporal_validity,
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
                    error!("Failed to insert causal relationship - DB interaction error: {}", e);
                    AppError::DbInteractError(e.to_string())
                })?
                .map_err(|e| {
                    error!("Failed to insert causal relationship (from: {}, to: {}, type: {}) - Database query error: {}", 
                           update.from_entity_id, update.to_entity_id, update.relationship_type, e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;
            }
        }

        Ok(())
    }

    /// Extract narrative context from chronicle event's context_data field
    fn extract_narrative_context_from_event(&self, event: &ChronicleEvent) -> Option<NarrativeContext> {
        let context_json = event.context_data.as_ref()
            .or_else(|| event.event_data.as_ref().and_then(|ed| ed.get("context_data")));

        context_json.and_then(|json| {
            match serde_json::from_value(json.clone()) {
                Ok(context) => Some(context),
                Err(e) => {
                    warn!("Failed to deserialize NarrativeContext from event {}: {}", event.id, e);
                    None
                }
            }
        })
    }

    /// Create a health component using narrative context if available
    fn create_health_component_from_context(
        &self,
        entity_data: Option<&EntityData>,
        narrative_context: Option<&NarrativeContext>
    ) -> Result<HealthComponent, AppError> {
        // Try to extract health information from narrative context
        if let Some(context) = narrative_context {
            let entity_name = entity_data.map(|d| d.name.as_str()).unwrap_or("Unknown");
            
            if let Some(entity) = context.entities.iter().find(|e| e.name == entity_name) {
                for prop in &entity.properties {
                    let prop_lower = prop.to_lowercase();
                    if prop_lower.contains("wounded") || prop_lower.contains("injured") {
                        return Ok(HealthComponent {
                            current: 50,
                            max: 100,
                            regeneration_rate: 0.5,
                        });
                    } else if prop_lower.contains("healthy") || prop_lower.contains("strong") {
                        return Ok(HealthComponent {
                            current: 100,
                            max: 100,
                            regeneration_rate: 1.5,
                        });
                    }
                }
            }
        }
        
        // Default health if no context available
        Ok(HealthComponent {
            current: 100,
            max: 100,
            regeneration_rate: 1.0,
        })
    }

    /// Create a position component using spatial context if available
    fn create_position_component_from_context(
        &self,
        entity_data: Option<&EntityData>,
        narrative_context: Option<&NarrativeContext>
    ) -> Result<PositionComponent, AppError> {
        // Try to extract spatial information from narrative context
        if let Some(context) = narrative_context {
            let entity_name = entity_data.map(|d| d.name.as_str()).unwrap_or("Unknown");

            // Check if there's a primary location
            if let Some(primary_location) = &context.spatial_context.primary_location {
                if !primary_location.is_empty() {
                    return Ok(PositionComponent {
                        x: 0.0,
                        y: 0.0,
                        z: 0.0,
                        zone: primary_location.clone(),
                    });
                }
            }

            // Check spatial relationships for this entity
            for rel in &context.spatial_context.spatial_relationships {
                if rel.entity1 == entity_name || rel.entity2 == entity_name {
                    // Use the location from the relationship
                    let location = if rel.entity1 == entity_name { &rel.entity2 } else { &rel.entity1 };
                    if !location.is_empty() {
                        return Ok(PositionComponent {
                            x: 0.0,
                            y: 0.0,
                            z: 0.0,
                            zone: format!("{} ({})", rel.relationship, location),
                        });
                    }
                }
            }
        }
        
        // Default position if no spatial context available
        Ok(PositionComponent {
            x: 0.0,
            y: 0.0,
            z: 0.0,
            zone: "unknown".to_string(),
        })
    }


    /// Create a description component using entity description from narrative context
    fn create_description_component_from_context(
        &self, 
        entity_data: Option<&EntityData>,
        narrative_context: Option<&NarrativeContext>
    ) -> Result<JsonValue, AppError> {
        let mut description = "No description available.".to_string();
        
        // Try to extract description from narrative context
        if let Some(context) = narrative_context {
            let entity_name = entity_data.map(|d| d.name.as_str()).unwrap_or("Unknown");
            if let Some(entity) = context.entities.iter().find(|e| e.name == entity_name) {
                if !entity.description.is_empty() {
                    description = entity.description.clone();
                }
            }
        }
        
        Ok(json!({
            "description": description,
            "source": "narrative_context"
        }))
    }

    /// Create contextual component data for various component types
    fn create_contextual_component(
        &self,
        component_type: &str,
        entity_data: Option<&EntityData>,
        narrative_context: Option<&NarrativeContext>
    ) -> Result<JsonValue, AppError> {
        let entity_name = entity_data.map(|d| d.name.as_str()).unwrap_or("Unknown");
        let entity_type = entity_data.map(|d| d.entity_type.as_str()).unwrap_or("UNKNOWN");
        
        let mut component_data = json!({
            "component_type": component_type,
            "entity_name": entity_name,
            "entity_type": entity_type,
            "confidence": entity_data.map(|d| d.confidence).unwrap_or(0.5)
        });
        
        // Add contextual data based on component type and available narrative context
        if let Some(context) = narrative_context {
            if let Some(entity) = context.entities.iter().find(|e| e.name == entity_name) {
                match component_type {
                    "Personality" => {
                        // More specific filtering for personality traits
                        let personality_keywords = ["brave", "cunning", "stoic", "deceptive", "friendly", "hostile", "kind", "cruel"];
                        let mut traits: Vec<String> = entity.properties.iter()
                            .filter(|p| personality_keywords.iter().any(|kw| p.to_lowercase().contains(kw)))
                            .map(|s| s.to_string())
                            .collect();
                        
                        // Add emotional tone as a mood
                        let mood = context.social_context.emotional_tone.clone();
                        if !traits.contains(&mood) {
                            traits.push(mood);
                        }

                        component_data["traits"] = json!(traits);
                        component_data["mood"] = json!(context.social_context.emotional_tone);
                    }
                    "Skills" => {
                        let mut skills: Vec<String> = entity.properties.iter()
                            .filter(|p| {
                                let p_lower = p.to_lowercase();
                                p_lower.contains("skill") || p_lower.contains("ability") || p_lower.contains("proficient")
                            })
                            .map(|s| s.to_string())
                            .collect();

                        // Infer skills from actions
                        for action in &context.actions_and_events {
                            if let Some(agent) = &action.agent {
                                if agent == entity_name {
                                    // Simple mapping from verb to skill noun
                                    let skill = match action.action.to_lowercase().as_str() {
                                        "attacked" | "fought" => "combat".to_string(),
                                        "negotiated" | "persuaded" => "diplomacy".to_string(),
                                        "crafted" | "built" => "crafting".to_string(),
                                        "healed" => "healing".to_string(),
                                        _ => continue,
                                    };
                                    if !skills.contains(&skill) {
                                        skills.push(skill);
                                    }
                                }
                            }
                        }
                        
                        if !skills.is_empty() {
                            component_data["skills"] = json!(skills);
                        }
                    }
                    "Environmental_Properties" => {
                        if let Some(primary_location) = &context.spatial_context.primary_location {
                            component_data["primary_environment"] = json!(primary_location);
                        }
                        if !context.spatial_context.secondary_locations.is_empty() {
                            component_data["nearby_environments"] = json!(context.spatial_context.secondary_locations);
                        }
                    }
                    "Spatial_Containment" => {
                        let mut contains = Vec::new();
                        let mut contained_by = Vec::new();
                        
                        for rel in &context.spatial_context.spatial_relationships {
                            if rel.entity1 == entity_name && (rel.relationship.contains("in") || rel.relationship.contains("contains")) {
                                contains.push(&rel.entity2);
                            } else if rel.entity2 == entity_name && (rel.relationship.contains("in") || rel.relationship.contains("contains")) {
                                contained_by.push(&rel.entity1);
                            }
                        }
                        
                        if !contains.is_empty() {
                            component_data["contains"] = json!(contains);
                        }
                        if !contained_by.is_empty() {
                            component_data["contained_by"] = json!(contained_by);
                        }
                    }
                    "Organizational_Structure" => {
                        let org_traits: Vec<&String> = entity.properties.iter()
                            .filter(|p| {
                                let p_lower = p.to_lowercase();
                                p_lower.contains("system") || p_lower.contains("organization") || p_lower.contains("department") || p_lower.contains("division")
                            })
                            .collect();
                        
                        if !org_traits.is_empty() {
                            component_data["structure_info"] = json!(org_traits);
                        }
                    }
                    "Operational_Status" => {
                        let status_indicators: Vec<&String> = entity.properties.iter()
                            .filter(|p| {
                                let p_lower = p.to_lowercase();
                                p_lower.contains("active") || p_lower.contains("inactive") || p_lower.contains("operational") || p_lower.contains("functional") || p_lower.contains("status")
                            })
                            .collect();
                        
                        if !status_indicators.is_empty() {
                            component_data["status"] = json!(status_indicators);
                        } else if entity_type == "ORGANIZATION" {
                            component_data["status"] = json!(["operational"]);
                        }
                    }
                    _ => {
                        // For other component types, just include basic properties
                        component_data["properties"] = json!({});
                    }
                }
            }
        }
        
        Ok(component_data)
    }
}