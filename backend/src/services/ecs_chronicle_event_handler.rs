// backend/src/services/ecs_chronicle_event_handler.rs
//
// ECS Chronicle Event Handler
//
// This service integrates the ECS outbox processor with the Chronicle system,
// handling ECS events and propagating them to Chronicle for narrative processing.

use std::sync::Arc;
use uuid::Uuid;
use serde_json::json;
use tracing::{info, debug, instrument};
use async_trait::async_trait;

use crate::{
    PgPool,
    errors::AppError,
    models::{
        ecs_diesel::EcsOutboxEvent,
        chronicle_event::{NewChronicleEvent, EventSource},
    },
    services::{
        OutboxEventHandler,
        ChronicleService,
        NarrativeIntelligenceService,
    },
    schema::chronicle_events,
};

use diesel::prelude::*;
use diesel::RunQueryDsl;

/// Configuration for the Chronicle event handler
#[derive(Debug, Clone)]
pub struct ChronicleEventHandlerConfig {
    /// Whether to enable narrative intelligence processing
    pub enable_narrative_processing: bool,
    /// Whether to batch chronicle events for performance
    pub enable_event_batching: bool,
    /// Maximum batch size for chronicle events
    pub max_batch_size: usize,
}

impl Default for ChronicleEventHandlerConfig {
    fn default() -> Self {
        Self {
            enable_narrative_processing: true,
            enable_event_batching: true,
            max_batch_size: 20,
        }
    }
}

/// Event handler that integrates ECS events with the Chronicle system
pub struct EcsChronicleEventHandler {
    db_pool: Arc<PgPool>,
    chronicle_service: Arc<ChronicleService>,
    narrative_intelligence: Arc<NarrativeIntelligenceService>,
    config: ChronicleEventHandlerConfig,
}

impl EcsChronicleEventHandler {
    /// Create a new ECS Chronicle event handler
    pub fn new(
        db_pool: Arc<PgPool>,
        chronicle_service: Arc<ChronicleService>,
        narrative_intelligence: Arc<NarrativeIntelligenceService>,
        config: Option<ChronicleEventHandlerConfig>,
    ) -> Self {
        let config = config.unwrap_or_default();
        
        info!("Initializing ECS Chronicle Event Handler with config: {:?}", config);
        
        Self {
            db_pool,
            chronicle_service,
            narrative_intelligence,
            config,
        }
    }

    /// Convert ECS event to Chronicle event
    #[instrument(skip(self, ecs_event))]
    async fn convert_to_chronicle_event(
        &self,
        ecs_event: &EcsOutboxEvent,
    ) -> Result<Option<NewChronicleEvent>, AppError> {
        match ecs_event.event_type.as_str() {
            "entity_created" => {
                self.handle_entity_created_event(ecs_event).await
            }
            "component_added" => {
                self.handle_component_added_event(ecs_event).await
            }
            "component_updated" => {
                self.handle_component_updated_event(ecs_event).await
            }
            "component_removed" => {
                self.handle_component_removed_event(ecs_event).await
            }
            "entity_destroyed" => {
                self.handle_entity_destroyed_event(ecs_event).await
            }
            "relationship_changed" => {
                self.handle_relationship_changed_event(ecs_event).await
            }
            _ => {
                debug!("Unknown ECS event type: {}", ecs_event.event_type);
                Ok(None)
            }
        }
    }

    async fn handle_entity_created_event(
        &self,
        ecs_event: &EcsOutboxEvent,
    ) -> Result<Option<NewChronicleEvent>, AppError> {
        let entity_id = ecs_event.entity_id.ok_or_else(|| {
            AppError::InvalidInput("Entity created event missing entity_id".to_string())
        })?;

        let chronicle_event = NewChronicleEvent {
            chronicle_id: Uuid::new_v4(), // This will need to be provided by the chronicle system
            user_id: ecs_event.user_id,
            event_type: "WORLD_BUILDING".to_string(),
            summary: format!(
                "A new entity {} has emerged in the world.",
                entity_id
            ),
            source: EventSource::System.to_string(),
            event_data: Some(json!({
                "ecs_event_id": ecs_event.id,
                "ecs_entity_id": entity_id,
                "archetype": ecs_event.event_data.get("archetype_signature"),
                "source": "ecs_system"
            })),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: chrono::Utc::now(),
            actors: Some(json!([{
                "entity_id": entity_id,
                "role": "SUBJECT"
            }])),
            action: Some("CREATE".to_string()),
            context_data: Some(ecs_event.event_data.clone()),
            causality: None,
            valence: Some(json!([{
                "type": "WORLD",
                "value": 0.2
            }])),
            modality: Some("ACTUAL".to_string()),
            // Enhanced causality tracking fields
            caused_by_event_id: None,
            causes_event_ids: None,
            sequence_number: 0, // Will be set by chronicle service
        };

        Ok(Some(chronicle_event))
    }

    async fn handle_component_added_event(
        &self,
        ecs_event: &EcsOutboxEvent,
    ) -> Result<Option<NewChronicleEvent>, AppError> {
        let entity_id = ecs_event.entity_id.ok_or_else(|| {
            AppError::InvalidInput("Component added event missing entity_id".to_string())
        })?;

        let component_type = ecs_event.component_type.as_ref().ok_or_else(|| {
            AppError::InvalidInput("Component added event missing component_type".to_string())
        })?;

        // Only create chronicle events for significant component types
        let should_chronicle = match component_type.as_str() {
            "Health" | "Position" | "Relationships" | "Inventory" => true,
            _ => false,
        };

        if !should_chronicle {
            return Ok(None);
        }

        let narrative_description = match component_type.as_str() {
            "Health" => format!("Entity {} gained vitality and can now be wounded or healed.", entity_id),
            "Position" => format!("Entity {} materialized at a specific location in the world.", entity_id),
            "Relationships" => format!("Entity {} began forming social connections with others.", entity_id),
            "Inventory" => format!("Entity {} became capable of carrying and using items.", entity_id),
            _ => format!("Entity {} acquired new capabilities ({}).", entity_id, component_type),
        };

        let chronicle_event = NewChronicleEvent {
            chronicle_id: Uuid::new_v4(),
            user_id: ecs_event.user_id,
            event_type: "CHARACTER".to_string(),
            summary: narrative_description,
            source: EventSource::System.to_string(),
            event_data: Some(json!({
                "ecs_event_id": ecs_event.id,
                "ecs_entity_id": entity_id,
                "component_type": component_type,
                "component_data": ecs_event.event_data.get("component_data"),
                "source": "ecs_system"
            })),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: chrono::Utc::now(),
            actors: Some(json!([{
                "entity_id": entity_id,
                "role": "SUBJECT"
            }])),
            action: Some("ACQUIRE".to_string()),
            context_data: Some(ecs_event.event_data.clone()),
            causality: None,
            valence: Some(json!([{
                "type": "CHARACTER",
                "value": 0.1
            }])),
            modality: Some("ACTUAL".to_string()),
            // Enhanced causality tracking fields
            caused_by_event_id: None,
            causes_event_ids: None,
            sequence_number: 0, // Will be set by chronicle service
        };

        Ok(Some(chronicle_event))
    }

    async fn handle_component_updated_event(
        &self,
        ecs_event: &EcsOutboxEvent,
    ) -> Result<Option<NewChronicleEvent>, AppError> {
        let entity_id = ecs_event.entity_id.ok_or_else(|| {
            AppError::InvalidInput("Component updated event missing entity_id".to_string())
        })?;

        let component_type = ecs_event.component_type.as_ref().ok_or_else(|| {
            AppError::InvalidInput("Component updated event missing component_type".to_string())
        })?;

        // Only chronicle significant component updates
        let (should_chronicle, emotional_valence, narrative_description) = match component_type.as_str() {
            "Health" => {
                if let Some(health_data) = ecs_event.event_data.get("component_data") {
                    if let (Some(current), Some(max)) = (
                        health_data.get("current").and_then(|v| v.as_i64()),
                        health_data.get("max").and_then(|v| v.as_i64())
                    ) {
                        let health_percentage = current as f64 / max as f64;
                        let emotional_impact = if health_percentage < 0.3 {
                            -0.4 // Severely wounded
                        } else if health_percentage < 0.7 {
                            -0.2 // Injured
                        } else if health_percentage > 0.9 {
                            0.2  // Fully healed
                        } else {
                            0.0  // Normal health changes
                        };

                        let description = if health_percentage < 0.3 {
                            format!("Entity {} is severely wounded and struggling to survive.", entity_id)
                        } else if health_percentage < 0.7 {
                            format!("Entity {} has been injured and needs care.", entity_id)
                        } else if health_percentage > 0.9 {
                            format!("Entity {} has recovered to full health.", entity_id)
                        } else {
                            format!("Entity {}'s health changed.", entity_id)
                        };

                        (health_percentage < 0.7 || health_percentage > 0.9, emotional_impact, description)
                    } else {
                        (false, 0.0, String::new())
                    }
                } else {
                    (false, 0.0, String::new())
                }
            }
            "Position" => {
                (true, 0.05, format!("Entity {} moved to a new location.", entity_id))
            }
            "Relationships" => {
                (true, 0.1, format!("Entity {}'s relationships with others changed.", entity_id))
            }
            _ => (false, 0.0, String::new()),
        };

        if !should_chronicle {
            return Ok(None);
        }

        let chronicle_event = NewChronicleEvent {
            chronicle_id: Uuid::new_v4(),
            user_id: ecs_event.user_id,
            event_type: "CHARACTER".to_string(),
            summary: narrative_description,
            source: EventSource::System.to_string(),
            event_data: Some(json!({
                "ecs_event_id": ecs_event.id,
                "ecs_entity_id": entity_id,
                "component_type": component_type,
                "component_data": ecs_event.event_data.get("component_data"),
                "source": "ecs_system"
            })),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: chrono::Utc::now(),
            actors: Some(json!([{
                "entity_id": entity_id,
                "role": "SUBJECT"
            }])),
            action: Some("CHANGE".to_string()),
            context_data: Some(ecs_event.event_data.clone()),
            causality: None,
            valence: Some(json!([{
                "type": "EMOTIONAL",
                "value": emotional_valence
            }])),
            modality: Some("ACTUAL".to_string()),
            // Enhanced causality tracking fields
            caused_by_event_id: None,
            causes_event_ids: None,
            sequence_number: 0, // Will be set by chronicle service
        };

        Ok(Some(chronicle_event))
    }

    async fn handle_component_removed_event(
        &self,
        ecs_event: &EcsOutboxEvent,
    ) -> Result<Option<NewChronicleEvent>, AppError> {
        let entity_id = ecs_event.entity_id.ok_or_else(|| {
            AppError::InvalidInput("Component removed event missing entity_id".to_string())
        })?;

        let component_type = ecs_event.component_type.as_ref().ok_or_else(|| {
            AppError::InvalidInput("Component removed event missing component_type".to_string())
        })?;

        // Component removal is usually significant
        let (narrative_description, emotional_valence) = match component_type.as_str() {
            "Health" => (
                format!("Entity {} lost their vitality and can no longer be affected by physical harm.", entity_id),
                -0.2
            ),
            "Position" => (
                format!("Entity {} faded from the physical world and can no longer be located.", entity_id),
                -0.1
            ),
            "Relationships" => (
                format!("Entity {} severed all social connections and became isolated.", entity_id),
                -0.3
            ),
            "Inventory" => (
                format!("Entity {} lost the ability to carry items.", entity_id),
                -0.1
            ),
            _ => (
                format!("Entity {} lost certain capabilities ({}).", entity_id, component_type),
                -0.05
            ),
        };

        let chronicle_event = NewChronicleEvent {
            chronicle_id: Uuid::new_v4(),
            user_id: ecs_event.user_id,
            event_type: "CHARACTER".to_string(),
            summary: narrative_description,
            source: EventSource::System.to_string(),
            event_data: Some(json!({
                "ecs_event_id": ecs_event.id,
                "ecs_entity_id": entity_id,
                "component_type": component_type,
                "source": "ecs_system"
            })),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: chrono::Utc::now(),
            actors: Some(json!([{
                "entity_id": entity_id,
                "role": "SUBJECT"
            }])),
            action: Some("LOSE".to_string()),
            context_data: Some(ecs_event.event_data.clone()),
            causality: None,
            valence: Some(json!([{
                "type": "EMOTIONAL",
                "value": emotional_valence
            }])),
            modality: Some("ACTUAL".to_string()),
            // Enhanced causality tracking fields
            caused_by_event_id: None,
            causes_event_ids: None,
            sequence_number: 0, // Will be set by chronicle service
        };

        Ok(Some(chronicle_event))
    }

    async fn handle_entity_destroyed_event(
        &self,
        ecs_event: &EcsOutboxEvent,
    ) -> Result<Option<NewChronicleEvent>, AppError> {
        let entity_id = ecs_event.entity_id.ok_or_else(|| {
            AppError::InvalidInput("Entity destroyed event missing entity_id".to_string())
        })?;

        let chronicle_event = NewChronicleEvent {
            chronicle_id: Uuid::new_v4(),
            user_id: ecs_event.user_id,
            event_type: "WORLD_BUILDING".to_string(),
            summary: format!(
                "Entity {} has been destroyed and is no longer part of the world.",
                entity_id
            ),
            source: EventSource::System.to_string(),
            event_data: Some(json!({
                "ecs_event_id": ecs_event.id,
                "ecs_entity_id": entity_id,
                "source": "ecs_system"
            })),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: chrono::Utc::now(),
            actors: Some(json!([{
                "entity_id": entity_id,
                "role": "SUBJECT"
            }])),
            action: Some("DESTROY".to_string()),
            context_data: Some(ecs_event.event_data.clone()),
            causality: None,
            valence: Some(json!([{
                "type": "WORLD",
                "value": -0.2
            }])),
            modality: Some("ACTUAL".to_string()),
            // Enhanced causality tracking fields
            caused_by_event_id: None,
            causes_event_ids: None,
            sequence_number: 0, // Will be set by chronicle service
        };

        Ok(Some(chronicle_event))
    }

    async fn handle_relationship_changed_event(
        &self,
        ecs_event: &EcsOutboxEvent,
    ) -> Result<Option<NewChronicleEvent>, AppError> {
        let entity_id = ecs_event.entity_id.ok_or_else(|| {
            AppError::InvalidInput("Relationship changed event missing entity_id".to_string())
        })?;

        // Extract relationship details from event data
        let relationship_data = ecs_event.event_data.get("relationship_data");
        let target_entity = relationship_data
            .and_then(|r| r.get("target_entity_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let relationship_type = relationship_data
            .and_then(|r| r.get("relationship_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let affection_change = relationship_data
            .and_then(|r| r.get("affection_change"))
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let emotional_valence = affection_change * 0.5; // Scale to appropriate range

        let narrative_description = if affection_change > 0.2 {
            format!("The relationship between {} and {} grew stronger ({}).", entity_id, target_entity, relationship_type)
        } else if affection_change < -0.2 {
            format!("The relationship between {} and {} deteriorated ({}).", entity_id, target_entity, relationship_type)
        } else {
            format!("The relationship between {} and {} shifted subtly ({}).", entity_id, target_entity, relationship_type)
        };

        let chronicle_event = NewChronicleEvent {
            chronicle_id: Uuid::new_v4(),
            user_id: ecs_event.user_id,
            event_type: "RELATIONSHIP".to_string(),
            summary: narrative_description,
            source: EventSource::System.to_string(),
            event_data: Some(json!({
                "ecs_event_id": ecs_event.id,
                "ecs_entity_id": entity_id,
                "target_entity_id": target_entity,
                "relationship_type": relationship_type,
                "affection_change": affection_change,
                "source": "ecs_system"
            })),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: chrono::Utc::now(),
            actors: Some(json!([
                {
                    "entity_id": entity_id,
                    "role": "SUBJECT"
                },
                {
                    "entity_id": target_entity,
                    "role": "OBJECT"
                }
            ])),
            action: Some("RELATE".to_string()),
            context_data: Some(ecs_event.event_data.clone()),
            causality: None,
            valence: Some(json!([{
                "type": "EMOTIONAL",
                "value": emotional_valence
            }])),
            modality: Some("ACTUAL".to_string()),
            // Enhanced causality tracking fields
            caused_by_event_id: None,
            causes_event_ids: None,
            sequence_number: 0, // Will be set by chronicle service
        };

        Ok(Some(chronicle_event))
    }

    async fn create_chronicle_event(&self, new_event: NewChronicleEvent) -> Result<(), AppError> {
        let conn = self.db_pool.get().await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        conn.interact(move |conn| -> Result<(), AppError> {
            diesel::insert_into(chronicle_events::table)
                .values(&new_event)
                .execute(conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            Ok(())
        }).await.map_err(|e| AppError::DbInteractError(e.to_string()))?
        .map_err(|e: AppError| e)?;

        info!("Created chronicle event from ECS event");
        Ok(())
    }
}

#[async_trait]
impl OutboxEventHandler for EcsChronicleEventHandler {
    async fn handle_event(&self, event: &EcsOutboxEvent) -> Result<(), AppError> {
        debug!("Processing ECS event {} of type {}", event.id, event.event_type);

        // Convert ECS event to Chronicle event
        let chronicle_event_opt = self.convert_to_chronicle_event(event).await?;

        if let Some(chronicle_event) = chronicle_event_opt {
            // Create the chronicle event
            self.create_chronicle_event(chronicle_event).await?;

            // Optionally trigger narrative intelligence processing
            if self.config.enable_narrative_processing {
                // Note: This could be done asynchronously to avoid blocking the outbox processor
                // For now, we'll just log that we would trigger processing
                debug!("Would trigger narrative intelligence processing for user {}", event.user_id);
            }
        }

        Ok(())
    }

    fn supported_event_types(&self) -> Vec<String> {
        vec![
            "entity_created".to_string(),
            "component_added".to_string(),
            "component_updated".to_string(),
            "component_removed".to_string(),
            "entity_destroyed".to_string(),
            "relationship_changed".to_string(),
        ]
    }
}