use crate::schema::chronicle_events;
use crate::models::narrative_ontology::{
    EventActor, EventCausality, EventModality, EventValence, NarrativeAction, NarrativeEvent
};
use chrono::{DateTime, Utc};
use diesel::{Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use serde_json::{self, Value as JsonValue};
use uuid::Uuid;
use validator::Validate;
use secrecy::ExposeSecret;

/// EventSource represents where a chronicle event originated from
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventSource {
    #[serde(rename = "USER_ADDED")]
    UserAdded,
    #[serde(rename = "AI_EXTRACTED")]
    AiExtracted,
    #[serde(rename = "GAME_API")]
    GameApi,
    #[serde(rename = "SYSTEM")]
    System,
}

impl std::fmt::Display for EventSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventSource::UserAdded => write!(f, "USER_ADDED"),
            EventSource::AiExtracted => write!(f, "AI_EXTRACTED"),
            EventSource::GameApi => write!(f, "GAME_API"),
            EventSource::System => write!(f, "SYSTEM"),
        }
    }
}

impl std::str::FromStr for EventSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "USER_ADDED" => Ok(EventSource::UserAdded),
            "AI_EXTRACTED" => Ok(EventSource::AiExtracted),
            "GAME_API" => Ok(EventSource::GameApi),
            "SYSTEM" => Ok(EventSource::System),
            _ => Err(format!("Unknown event source: {}", s)),
        }
    }
}

/// ChronicleEvent represents a single event within a chronicle
/// Enhanced with Ars Fabula narrative ontology fields
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = chronicle_events)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ChronicleEvent {
    pub id: Uuid,
    pub chronicle_id: Uuid,
    pub user_id: Uuid,
    pub event_type: String,
    pub summary: String, // Legacy field - will be deprecated
    pub source: String, // Will be converted to/from EventSource
    pub event_data: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub summary_encrypted: Option<Vec<u8>>,
    pub summary_nonce: Option<Vec<u8>>,
    // New Ars Fabula fields
    pub timestamp_iso8601: DateTime<Utc>,
    pub actors: Option<JsonValue>,
    pub action: Option<String>,
    pub context_data: Option<JsonValue>,
    pub causality: Option<JsonValue>,
    pub valence: Option<JsonValue>,
    pub modality: Option<String>,
}

impl ChronicleEvent {
    /// Get the event source as an enum
    pub fn get_source(&self) -> Result<EventSource, String> {
        self.source.parse()
    }

    /// Helper to check if this event has additional data
    pub fn has_event_data(&self) -> bool {
        self.event_data.is_some()
    }

    /// Get the decrypted summary using the provided DEK
    /// Falls back to legacy plaintext summary if encrypted version is not available
    pub fn get_decrypted_summary(&self, dek: &secrecy::SecretBox<Vec<u8>>) -> Result<String, crate::errors::AppError> {
        match (&self.summary_encrypted, &self.summary_nonce) {
            (Some(encrypted), Some(nonce)) => {
                // Decrypt the summary
                let decrypted_secret = crate::crypto::decrypt_gcm(encrypted, nonce, dek)
                    .map_err(|e| crate::errors::AppError::CryptoError(e.to_string()))?;
                let decrypted_bytes = decrypted_secret.expose_secret();
                String::from_utf8(decrypted_bytes.clone())
                    .map_err(|e| crate::errors::AppError::SerializationError(
                        format!("Failed to convert decrypted summary to UTF-8: {}", e)
                    ))
            }
            _ => {
                // Fall back to legacy plaintext summary
                Ok(self.summary.clone())
            }
        }
    }

    /// Check if this event has encrypted summary
    pub fn has_encrypted_summary(&self) -> bool {
        self.summary_encrypted.is_some() && self.summary_nonce.is_some()
    }

    /// Get the actors involved in this event
    pub fn get_actors(&self) -> Result<Vec<EventActor>, serde_json::Error> {
        match &self.actors {
            Some(json) => serde_json::from_value(json.clone()),
            None => Ok(Vec::new()),
        }
    }

    /// Get the narrative action for this event
    pub fn get_action(&self) -> Option<NarrativeAction> {
        self.action.as_ref().and_then(|action_str| {
            serde_json::from_str::<NarrativeAction>(&format!("\"{}\"", action_str)).ok()
        })
    }

    /// Get the causality relationships for this event
    pub fn get_causality(&self) -> Result<EventCausality, serde_json::Error> {
        match &self.causality {
            Some(json) => serde_json::from_value(json.clone()),
            None => Ok(EventCausality::default()),
        }
    }

    /// Get the valence (emotional/relational impacts) for this event
    pub fn get_valence(&self) -> Result<Vec<EventValence>, serde_json::Error> {
        match &self.valence {
            Some(json) => serde_json::from_value(json.clone()),
            None => Ok(Vec::new()),
        }
    }

    /// Get the event modality (reality status)
    pub fn get_modality(&self) -> EventModality {
        match &self.modality {
            Some(modality_str) => {
                serde_json::from_str::<EventModality>(&format!("\"{}\"", modality_str))
                    .unwrap_or_default()
            }
            None => EventModality::default(),
        }
    }

    /// Convert this ChronicleEvent to a full NarrativeEvent
    pub fn to_narrative_event(&self) -> Result<NarrativeEvent, Box<dyn std::error::Error>> {
        let actors = self.get_actors()?;
        let action = self.get_action().unwrap_or(NarrativeAction::Custom("UNKNOWN".to_string()));
        let causality = self.get_causality()?;
        let valence = self.get_valence()?;
        let modality = self.get_modality();

        Ok(NarrativeEvent {
            event_id: self.id,
            timestamp: self.timestamp_iso8601,
            event_type: self.event_type.clone(),
            actors,
            action,
            object: None, // Not stored in current schema
            context: None, // Could be extracted from context_data
            causality,
            valence,
            modality,
            summary: self.summary.clone(),
            metadata: self.event_data.clone(),
        })
    }

    /// Check if this event involves a specific entity
    pub fn involves_entity(&self, entity_id: &Uuid) -> bool {
        if let Ok(actors) = self.get_actors() {
            actors.iter().any(|actor| &actor.entity_id == entity_id)
        } else {
            false
        }
    }

    /// Check for potential duplicate based on Ars Fabula criteria
    pub fn is_potential_duplicate(&self, other: &ChronicleEvent) -> bool {
        // Same action and close timestamp (within 5 minutes)
        if let (Some(self_action), Some(other_action)) = (&self.action, &other.action) {
            if self_action == other_action {
                let time_diff = (self.timestamp_iso8601 - other.timestamp_iso8601).num_minutes().abs();
                if time_diff <= 5 {
                    // Check if actors overlap
                    if let (Ok(self_actors), Ok(other_actors)) = (self.get_actors(), other.get_actors()) {
                        let self_entities: std::collections::HashSet<_> = self_actors.iter().map(|a| a.entity_id).collect();
                        let other_entities: std::collections::HashSet<_> = other_actors.iter().map(|a| a.entity_id).collect();
                        
                        // If there's significant overlap in entities, it's a potential duplicate
                        let intersection_count = self_entities.intersection(&other_entities).count();
                        let union_count = self_entities.union(&other_entities).count();
                        
                        if union_count > 0 {
                            let overlap_ratio = intersection_count as f32 / union_count as f32;
                            return overlap_ratio >= 0.5; // 50% overlap threshold
                        }
                    }
                }
            }
        }
        false
    }
}

/// NewChronicleEvent for creating new events
/// Enhanced with Ars Fabula narrative ontology fields
#[derive(Debug, Clone, Insertable, Serialize, Deserialize, Validate)]
#[diesel(table_name = chronicle_events)]
pub struct NewChronicleEvent {
    pub chronicle_id: Uuid,
    pub user_id: Uuid,
    #[validate(length(min = 1, max = 100, message = "Event type must be between 1 and 100 characters"))]
    pub event_type: String,
    #[validate(length(min = 1, max = 5000, message = "Event summary must be between 1 and 5000 characters"))]
    pub summary: String, // Legacy field - will be deprecated
    pub source: String, // EventSource as string
    pub event_data: Option<JsonValue>,
    pub summary_encrypted: Option<Vec<u8>>,
    pub summary_nonce: Option<Vec<u8>>,
    // New Ars Fabula fields
    pub timestamp_iso8601: DateTime<Utc>,
    pub actors: Option<JsonValue>,
    pub action: Option<String>,
    pub context_data: Option<JsonValue>,
    pub causality: Option<JsonValue>,
    pub valence: Option<JsonValue>,
    pub modality: Option<String>,
}

impl NewChronicleEvent {
    /// Create a new event with EventSource enum (legacy method)
    pub fn new(
        chronicle_id: Uuid,
        user_id: Uuid,
        event_type: String,
        summary: String,
        source: EventSource,
        event_data: Option<JsonValue>,
    ) -> Self {
        Self {
            chronicle_id,
            user_id,
            event_type,
            summary,
            source: source.to_string(),
            event_data,
            summary_encrypted: None, // Will be set by service if encryption is available
            summary_nonce: None,     // Will be set by service if encryption is available
            timestamp_iso8601: Utc::now(),
            actors: None,
            action: None,
            context_data: None,
            causality: None,
            valence: None,
            modality: Some("ACTUAL".to_string()),
        }
    }

    /// Create a new event from a NarrativeEvent (enhanced method)
    pub fn from_narrative_event(
        chronicle_id: Uuid,
        user_id: Uuid,
        narrative_event: &NarrativeEvent,
        source: EventSource,
    ) -> Result<Self, serde_json::Error> {
        let actors_json = if narrative_event.actors.is_empty() {
            None
        } else {
            Some(serde_json::to_value(&narrative_event.actors)?)
        };

        let action_str = match &narrative_event.action {
            NarrativeAction::Custom(s) => s.clone(),
            _ => serde_json::to_string(&narrative_event.action)?.trim_matches('"').to_string(),
        };

        let causality_json = if narrative_event.causality.caused_by.is_empty() && narrative_event.causality.causes.is_empty() {
            None
        } else {
            Some(serde_json::to_value(&narrative_event.causality)?)
        };

        let valence_json = if narrative_event.valence.is_empty() {
            None
        } else {
            Some(serde_json::to_value(&narrative_event.valence)?)
        };

        let modality_str = match &narrative_event.modality {
            EventModality::Actual => "ACTUAL".to_string(),
            EventModality::Hypothetical => "HYPOTHETICAL".to_string(),
            EventModality::Counterfactual => "COUNTERFACTUAL".to_string(),
            EventModality::BelievedBy(agent_id) => format!("BELIEVED_BY:{}", agent_id),
        };

        Ok(Self {
            chronicle_id,
            user_id,
            event_type: narrative_event.event_type.clone(),
            summary: narrative_event.summary.clone(),
            source: source.to_string(),
            event_data: narrative_event.metadata.clone(),
            summary_encrypted: None, // Will be set by service if encryption is available
            summary_nonce: None,     // Will be set by service if encryption is available
            timestamp_iso8601: narrative_event.timestamp,
            actors: actors_json,
            action: Some(action_str),
            context_data: narrative_event.context.as_ref().and_then(|ctx| serde_json::to_value(ctx).ok()),
            causality: causality_json,
            valence: valence_json,
            modality: Some(modality_str),
        })
    }
}

/// UpdateChronicleEvent for updating existing events
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UpdateChronicleEvent {
    #[validate(length(min = 1, max = 100, message = "Event type must be between 1 and 100 characters"))]
    pub event_type: Option<String>,
    #[validate(length(min = 1, max = 5000, message = "Event summary must be between 1 and 5000 characters"))]
    pub summary: Option<String>,
    pub source: Option<EventSource>,
    pub event_data: Option<JsonValue>,
}

/// DTO for event creation from API
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateEventRequest {
    #[validate(length(min = 1, max = 100, message = "Event type must be between 1 and 100 characters"))]
    pub event_type: String,
    #[validate(length(min = 1, max = 5000, message = "Event summary must be between 1 and 5000 characters"))]
    pub summary: String,
    #[serde(default = "default_event_source")]
    pub source: EventSource,
    pub event_data: Option<JsonValue>,
}

fn default_event_source() -> EventSource {
    EventSource::UserAdded
}

/// DTO for event update from API
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UpdateEventRequest {
    #[validate(length(min = 1, max = 100, message = "Event type must be between 1 and 100 characters"))]
    pub event_type: Option<String>,
    #[validate(length(min = 1, max = 5000, message = "Event summary must be between 1 and 5000 characters"))]
    pub summary: Option<String>,
    pub source: Option<EventSource>,
    pub event_data: Option<JsonValue>,
}

/// Filter options for querying events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    pub event_type: Option<String>,
    pub source: Option<EventSource>,
    pub action: Option<String>,
    pub modality: Option<String>,
    pub involves_entity: Option<Uuid>,
    pub after_timestamp: Option<DateTime<Utc>>,
    pub before_timestamp: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub order_by: Option<EventOrderBy>,
}

/// Deduplication filter for finding potential duplicate events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationFilter {
    pub action: String,
    pub chronicle_id: Uuid,
    pub user_id: Uuid,
    pub window_minutes: i64, // Time window for checking duplicates
    pub similarity_threshold: f32, // Threshold for actor overlap (0.0-1.0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventOrderBy {
    #[serde(rename = "created_at_asc")]
    CreatedAtAsc,
    #[serde(rename = "created_at_desc")]
    CreatedAtDesc,
    #[serde(rename = "updated_at_asc")]
    UpdatedAtAsc,
    #[serde(rename = "updated_at_desc")]
    UpdatedAtDesc,
}

impl Default for EventFilter {
    fn default() -> Self {
        Self {
            event_type: None,
            source: None,
            action: None,
            modality: None,
            involves_entity: None,
            after_timestamp: None,
            before_timestamp: None,
            limit: Some(50),
            offset: Some(0),
            order_by: Some(EventOrderBy::CreatedAtDesc),
        }
    }
}

impl From<CreateEventRequest> for NewChronicleEvent {
    fn from(request: CreateEventRequest) -> Self {
        // Extract Ars Fabula data from the generic event_data blob
        let actors = request.event_data.as_ref().and_then(|data| data.get("actors").cloned());
        
        // Extract action - handle both string and NarrativeAction enum serialization
        let action = request.event_data.as_ref().and_then(|data| {
            data.get("action").and_then(|action_value| {
                // First try as a simple string
                if let Some(action_str) = action_value.as_str() {
                    Some(action_str.to_string())
                } else {
                    // Try to deserialize as NarrativeAction enum
                    serde_json::from_value::<NarrativeAction>(action_value.clone()).ok().map(|na| {
                        match na {
                            NarrativeAction::Custom(s) => s,
                            _ => serde_json::to_string(&na).unwrap_or_default().trim_matches('"').to_string(),
                        }
                    })
                }
            })
        });
        
        // Extract modality - handle both string and EventModality enum serialization
        let modality = request.event_data.as_ref().and_then(|data| {
            data.get("modality").and_then(|modality_value| {
                // First try as a simple string
                if let Some(modality_str) = modality_value.as_str() {
                    Some(modality_str.to_string())
                } else {
                    // Try to deserialize as EventModality enum
                    serde_json::from_value::<EventModality>(modality_value.clone()).ok().map(|em| {
                        match em {
                            EventModality::Actual => "ACTUAL".to_string(),
                            EventModality::Hypothetical => "HYPOTHETICAL".to_string(),
                            EventModality::Counterfactual => "COUNTERFACTUAL".to_string(),
                            EventModality::BelievedBy(agent_id) => format!("BELIEVED_BY:{}", agent_id),
                        }
                    })
                }
            })
        });
        let causality = request.event_data.as_ref().and_then(|data| data.get("causality").cloned());
        let valence = request.event_data.as_ref().and_then(|data| data.get("valence").cloned());
        
        // Extract timestamp from event_data if provided, otherwise use current time
        let timestamp = request.event_data.as_ref()
            .and_then(|data| data.get("timestamp_iso8601"))
            .and_then(|ts| ts.as_str())
            .and_then(|ts_str| chrono::DateTime::parse_from_rfc3339(ts_str).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(Utc::now);

        Self {
            chronicle_id: Uuid::nil(), // Will be set by the service
            user_id: Uuid::nil(),      // Will be set by the service
            event_type: request.event_type,
            summary: request.summary,
            source: request.source.to_string(),
            event_data: request.event_data,
            summary_encrypted: None, // Will be set by service if encryption is available
            summary_nonce: None,     // Will be set by service if encryption is available
            timestamp_iso8601: timestamp,
            actors,
            action,
            context_data: None, // Not typically provided in a simple request
            causality,
            valence,
            modality: modality.or(Some("ACTUAL".to_string())),
        }
    }
}

impl From<UpdateEventRequest> for UpdateChronicleEvent {
    fn from(request: UpdateEventRequest) -> Self {
        Self {
            event_type: request.event_type,
            summary: request.summary,
            source: request.source,
            event_data: request.event_data,
        }
    }
}