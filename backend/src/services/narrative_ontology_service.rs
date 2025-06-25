//! Narrative Ontology Service
//! 
//! Provides conversion and management services between the Ars Fabula formal 
//! narrative ontology and the existing chronicle event system.

use crate::{
    errors::AppError,
    models::{
        chronicle_event::{ChronicleEvent, CreateEventRequest, EventSource, NewChronicleEvent},
        narrative_ontology::{
            NarrativeEvent, NarrativeEventBuilder, ActorRole, NarrativeAction, EventActor, EventContext
        },
    },
};
use serde_json::{json, Value as JsonValue};
use uuid::Uuid;
use tracing::{debug, info, warn};

/// Service for managing narrative ontology conversions and operations
#[derive(Clone)]
pub struct NarrativeOntologyService;

impl NarrativeOntologyService {
    pub fn new() -> Self {
        Self
    }

    /// Convert a NarrativeEvent from the Ars Fabula ontology to a ChronicleEvent
    /// for storage in our existing database schema
    pub fn narrative_event_to_chronicle_event(
        &self,
        narrative_event: &NarrativeEvent,
        user_id: Uuid,
        chronicle_id: Uuid,
    ) -> Result<NewChronicleEvent, AppError> {
        debug!("Converting NarrativeEvent {} to ChronicleEvent", narrative_event.event_id);

        // Convert the event to our existing chronicle event format
        let event_data = self.serialize_narrative_event_data(narrative_event)?;

        let new_event = NewChronicleEvent {
            chronicle_id,
            user_id,
            event_type: narrative_event.event_type.clone(),
            summary: narrative_event.summary.clone(),
            source: EventSource::AiExtracted.to_string(),
            event_data: Some(event_data),
        };

        info!(
            "Converted NarrativeEvent {} of type {} to ChronicleEvent", 
            narrative_event.event_id, 
            narrative_event.event_type
        );

        Ok(new_event)
    }

    /// Convert a ChronicleEvent back to a NarrativeEvent (best effort reconstruction)
    pub fn chronicle_event_to_narrative_event(
        &self,
        chronicle_event: &ChronicleEvent,
    ) -> Result<NarrativeEvent, AppError> {
        debug!("Converting ChronicleEvent {} to NarrativeEvent", chronicle_event.id);

        // Start with basic event structure
        let mut narrative_event = NarrativeEvent::new(
            chronicle_event.event_type.clone(),
            self.infer_action_from_event_type(&chronicle_event.event_type),
            chronicle_event.summary.clone(),
        );

        // Override the generated UUID and timestamp with the stored ones
        narrative_event.event_id = chronicle_event.id;
        narrative_event.timestamp = chronicle_event.created_at;

        // Deserialize additional data if present
        if let Some(event_data) = &chronicle_event.event_data {
            self.deserialize_narrative_event_data(&mut narrative_event, event_data)?;
        }

        info!(
            "Converted ChronicleEvent {} of type {} to NarrativeEvent", 
            chronicle_event.id, 
            chronicle_event.event_type
        );

        Ok(narrative_event)
    }

    /// Create a CreateEventRequest from a NarrativeEvent for API compatibility
    pub fn narrative_event_to_create_request(
        &self,
        narrative_event: &NarrativeEvent,
    ) -> Result<CreateEventRequest, AppError> {
        let event_data = self.serialize_narrative_event_data(narrative_event)?;

        Ok(CreateEventRequest {
            event_type: narrative_event.event_type.clone(),
            summary: narrative_event.summary.clone(),
            source: EventSource::AiExtracted,
            event_data: Some(event_data),
        })
    }

    /// Serialize the rich NarrativeEvent data into JSON for storage
    fn serialize_narrative_event_data(&self, event: &NarrativeEvent) -> Result<JsonValue, AppError> {
        let mut data = json!({
            "ars_fabula_version": "1.0",
            "event_id": event.event_id,
            "timestamp": event.timestamp.to_rfc3339(),
            "action": event.action,
            "modality": event.modality
        });

        // Serialize actors
        if !event.actors.is_empty() {
            data["actors"] = json!(event.actors);
        }

        // Serialize object
        if let Some(object_id) = event.object {
            data["object"] = json!(object_id);
        }

        // Serialize context
        if let Some(context) = &event.context {
            data["context"] = serde_json::to_value(context)
                .map_err(|e| AppError::SerializationError(format!("Failed to serialize context: {}", e)))?;
        }

        // Serialize causality
        if !event.causality.caused_by.is_empty() || !event.causality.causes.is_empty() {
            data["causality"] = serde_json::to_value(&event.causality)
                .map_err(|e| AppError::SerializationError(format!("Failed to serialize causality: {}", e)))?;
        }

        // Serialize valence
        if !event.valence.is_empty() {
            data["valence"] = serde_json::to_value(&event.valence)
                .map_err(|e| AppError::SerializationError(format!("Failed to serialize valence: {}", e)))?;
        }

        // Serialize metadata
        if let Some(metadata) = &event.metadata {
            data["metadata"] = metadata.clone();
        }

        Ok(data)
    }

    /// Deserialize JSON data back into NarrativeEvent fields
    fn deserialize_narrative_event_data(
        &self,
        event: &mut NarrativeEvent,
        data: &JsonValue,
    ) -> Result<(), AppError> {
        // Check if this is Ars Fabula format
        if data.get("ars_fabula_version").is_none() {
            // Legacy format - try to extract what we can
            self.deserialize_legacy_event_data(event, data)?;
            return Ok(());
        }

        // Deserialize actors
        if let Some(actors_value) = data.get("actors") {
            event.actors = serde_json::from_value(actors_value.clone())
                .map_err(|e| AppError::SerializationError(format!("Failed to deserialize actors: {}", e)))?;
        }

        // Deserialize object
        if let Some(object_value) = data.get("object") {
            if let Some(object_str) = object_value.as_str() {
                event.object = Some(Uuid::parse_str(object_str)
                    .map_err(|e| AppError::SerializationError(format!("Invalid object UUID: {}", e)))?);
            }
        }

        // Deserialize context
        if let Some(context_value) = data.get("context") {
            event.context = Some(serde_json::from_value(context_value.clone())
                .map_err(|e| AppError::SerializationError(format!("Failed to deserialize context: {}", e)))?);
        }

        // Deserialize causality
        if let Some(causality_value) = data.get("causality") {
            event.causality = serde_json::from_value(causality_value.clone())
                .map_err(|e| AppError::SerializationError(format!("Failed to deserialize causality: {}", e)))?;
        }

        // Deserialize valence
        if let Some(valence_value) = data.get("valence") {
            event.valence = serde_json::from_value(valence_value.clone())
                .map_err(|e| AppError::SerializationError(format!("Failed to deserialize valence: {}", e)))?;
        }

        // Deserialize action
        if let Some(action_value) = data.get("action") {
            event.action = serde_json::from_value(action_value.clone())
                .map_err(|e| AppError::SerializationError(format!("Failed to deserialize action: {}", e)))?;
        }

        // Deserialize modality
        if let Some(modality_value) = data.get("modality") {
            event.modality = serde_json::from_value(modality_value.clone())
                .map_err(|e| AppError::SerializationError(format!("Failed to deserialize modality: {}", e)))?;
        }

        // Deserialize metadata
        if let Some(metadata_value) = data.get("metadata") {
            event.metadata = Some(metadata_value.clone());
        }

        Ok(())
    }

    /// Handle legacy event data format (backward compatibility)
    fn deserialize_legacy_event_data(
        &self,
        event: &mut NarrativeEvent,
        data: &JsonValue,
    ) -> Result<(), AppError> {
        warn!("Deserializing legacy event data format for event {}", event.event_id);

        // Extract legacy fields and map them to new structure
        if let Some(participants) = data.get("participants").and_then(|v| v.as_array()) {
            for participant_value in participants {
                if let Some(participant_name) = participant_value.as_str() {
                    // Create a placeholder UUID for legacy participant names  
                    // In a real system, you'd want to resolve these to actual entity IDs
                    let placeholder_id = Uuid::new_v4(); // Use v4 for now since v5 needs feature flag
                    event.actors.push(EventActor {
                        entity_id: placeholder_id,
                        role: ActorRole::Agent, // Default to agent role
                        context: Some(format!("Legacy participant: {}", participant_name)),
                    });
                }
            }
        }

        // Extract legacy location
        if let Some(location) = data.get("location").and_then(|v| v.as_str()) {
            let context = event.context.get_or_insert_with(|| EventContext {
                location_id: None,
                sub_location: Some(location.to_string()),
                time_of_day: None,
                weather: None,
                social_context: None,
                environmental_factors: None,
            });
            if context.sub_location.is_none() {
                context.sub_location = Some(location.to_string());
            }
        }

        // Extract legacy details
        if let Some(details) = data.get("details").and_then(|v| v.as_str()) {
            event.metadata = Some(json!({
                "legacy_details": details
            }));
        }

        Ok(())
    }

    /// Infer the narrative action from the event type string
    fn infer_action_from_event_type(&self, event_type: &str) -> NarrativeAction {
        let type_lower = event_type.to_lowercase();
        
        if type_lower.contains("death") || type_lower.contains("died") {
            NarrativeAction::Died
        } else if type_lower.contains("met") || type_lower.contains("meeting") {
            NarrativeAction::Met
        } else if type_lower.contains("discovered") || type_lower.contains("discovery") {
            NarrativeAction::Discovered
        } else if type_lower.contains("revealed") || type_lower.contains("revelation") {
            NarrativeAction::Revealed
        } else if type_lower.contains("acquired") || type_lower.contains("acquisition") {
            NarrativeAction::Acquired
        } else if type_lower.contains("betrayed") || type_lower.contains("betrayal") {
            NarrativeAction::Betrayed
        } else if type_lower.contains("attacked") || type_lower.contains("attack") {
            NarrativeAction::Attacked
        } else if type_lower.contains("defeated") || type_lower.contains("defeat") {
            NarrativeAction::Defeated
        } else if type_lower.contains("transformed") || type_lower.contains("transformation") {
            NarrativeAction::Transformed
        } else if type_lower.contains("told") || type_lower.contains("communication") {
            NarrativeAction::Told
        } else if type_lower.contains("decided") || type_lower.contains("decision") {
            NarrativeAction::Decided
        } else {
            // Fallback to custom action with the event type
            NarrativeAction::Custom(event_type.to_string())
        }
    }

    /// Create a narrative event using the builder pattern for common scenarios
    pub fn create_character_death_event(
        &self,
        victim_id: Uuid,
        killer_id: Option<Uuid>,
        location_id: Option<Uuid>,
        cause: String,
    ) -> NarrativeEvent {
        let mut builder = NarrativeEventBuilder::new(
            "CHARACTER.STATE_CHANGE.DEATH".to_string(),
            NarrativeAction::Died,
            format!("Character died: {}", cause),
        )
        .patient(victim_id);

        if let Some(killer) = killer_id {
            builder = builder.agent(killer);
        }

        if let Some(location) = location_id {
            builder = builder.at_location(location);
        }

        builder.build()
    }

    /// Create a narrative event for character meetings
    pub fn create_character_meeting_event(
        &self,
        character1_id: Uuid,
        character2_id: Uuid,
        location_id: Option<Uuid>,
        relationship_change: Option<f32>,
    ) -> NarrativeEvent {
        let mut builder = NarrativeEventBuilder::new(
            "RELATIONSHIP.FORMATION.FIRST_MEETING".to_string(),
            NarrativeAction::Met,
            "Two characters met for the first time".to_string(),
        )
        .agent(character1_id)
        .patient(character2_id);

        if let Some(location) = location_id {
            builder = builder.at_location(location);
        }

        if let Some(change) = relationship_change {
            builder = builder.impacts_affection(character1_id, change);
            builder = builder.impacts_affection(character2_id, change);
        }

        builder.build()
    }

    /// Create a narrative event for discoveries
    pub fn create_discovery_event(
        &self,
        discoverer_id: Uuid,
        discovered_entity_id: Uuid,
        location_id: Option<Uuid>,
        discovery_type: &str,
        summary: String,
    ) -> NarrativeEvent {
        let event_type = match discovery_type {
            "location" => "WORLD.DISCOVERY.LOCATION",
            "item" => "WORLD.DISCOVERY.ITEM", 
            "secret" => "PLOT.REVELATION.SECRET",
            "character" => "RELATIONSHIP.FORMATION.CHARACTER_MET",
            _ => "WORLD.DISCOVERY.UNKNOWN",
        };

        let mut builder = NarrativeEventBuilder::new(
            event_type.to_string(),
            NarrativeAction::Discovered,
            summary,
        )
        .agent(discoverer_id)
        .object(discovered_entity_id);

        if let Some(location) = location_id {
            builder = builder.at_location(location);
        }

        builder.build()
    }

    /// Validate that a NarrativeEvent is well-formed
    pub fn validate_narrative_event(&self, event: &NarrativeEvent) -> Result<(), AppError> {
        // Basic validation
        if event.event_type.is_empty() {
            return Err(AppError::InternalServerErrorGeneric("Event type cannot be empty".to_string()));
        }

        if event.summary.is_empty() {
            return Err(AppError::InternalServerErrorGeneric("Event summary cannot be empty".to_string()));
        }

        // Validate that we have at least one agent for most actions
        match event.action {
            NarrativeAction::Met | NarrativeAction::Attacked | NarrativeAction::Told => {
                if event.get_primary_agent().is_none() {
                    return Err(AppError::InternalServerErrorGeneric(
                        format!("Action {:?} requires at least one agent", event.action)
                    ));
                }
            }
            _ => {} // Other actions may not require agents
        }

        // Validate valence values are in reasonable range
        for valence in &event.valence {
            if valence.change < -1.0 || valence.change > 1.0 {
                return Err(AppError::InternalServerErrorGeneric(
                    format!("Valence change {} is outside valid range [-1.0, 1.0]", valence.change)
                ));
            }
        }

        // Validate causality confidence
        if event.causality.confidence < 0.0 || event.causality.confidence > 1.0 {
            return Err(AppError::InternalServerErrorGeneric(
                format!("Causality confidence {} is outside valid range [0.0, 1.0]", event.causality.confidence)
            ));
        }

        Ok(())
    }
}

impl Default for NarrativeOntologyService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::narrative_ontology::{EventModality, ValenceType};

    #[test]
    fn test_narrative_to_chronicle_conversion() {
        let service = NarrativeOntologyService::new();
        let user_id = Uuid::new_v4();
        let chronicle_id = Uuid::new_v4();
        let character_id = Uuid::new_v4();

        let narrative_event = NarrativeEventBuilder::new(
            "CHARACTER.DEVELOPMENT.SKILL_GAINED".to_string(),
            NarrativeAction::Acquired,
            "The hero learned swordplay".to_string(),
        )
        .agent(character_id)
        .impacts_trust(character_id, 0.1)
        .build();

        let chronicle_event = service
            .narrative_event_to_chronicle_event(&narrative_event, user_id, chronicle_id)
            .unwrap();

        assert_eq!(chronicle_event.event_type, "CHARACTER.DEVELOPMENT.SKILL_GAINED");
        assert_eq!(chronicle_event.summary, "The hero learned swordplay");
        assert_eq!(chronicle_event.user_id, user_id);
        assert_eq!(chronicle_event.chronicle_id, chronicle_id);
        assert!(chronicle_event.event_data.is_some());
    }

    #[test]
    fn test_action_inference() {
        let service = NarrativeOntologyService::new();

        assert_eq!(
            service.infer_action_from_event_type("CHARACTER_DEATH"),
            NarrativeAction::Died
        );
        assert_eq!(
            service.infer_action_from_event_type("character.met"),
            NarrativeAction::Met
        );
        assert_eq!(
            service.infer_action_from_event_type("LOCATION_DISCOVERED"),
            NarrativeAction::Discovered
        );
    }

    #[test]
    fn test_validate_narrative_event() {
        let service = NarrativeOntologyService::new();
        
        // Valid event
        let valid_event = NarrativeEventBuilder::new(
            "CHARACTER.DEVELOPMENT.SKILL_GAINED".to_string(),
            NarrativeAction::Acquired,
            "Valid event".to_string(),
        ).build();
        
        assert!(service.validate_narrative_event(&valid_event).is_ok());

        // Invalid event - empty type
        let invalid_event = NarrativeEvent::new(
            "".to_string(),
            NarrativeAction::Acquired,
            "Invalid event".to_string(),
        );
        
        assert!(service.validate_narrative_event(&invalid_event).is_err());
    }
}