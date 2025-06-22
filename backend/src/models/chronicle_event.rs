use crate::schema::chronicle_events;
use chrono::{DateTime, Utc};
use diesel::{Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;
use validator::Validate;

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
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = chronicle_events)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ChronicleEvent {
    pub id: Uuid,
    pub chronicle_id: Uuid,
    pub user_id: Uuid,
    pub event_type: String,
    pub summary: String,
    pub source: String, // Will be converted to/from EventSource
    pub event_data: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
}

/// NewChronicleEvent for creating new events
#[derive(Debug, Clone, Insertable, Serialize, Deserialize, Validate)]
#[diesel(table_name = chronicle_events)]
pub struct NewChronicleEvent {
    pub chronicle_id: Uuid,
    pub user_id: Uuid,
    #[validate(length(min = 1, max = 100, message = "Event type must be between 1 and 100 characters"))]
    pub event_type: String,
    #[validate(length(min = 1, max = 5000, message = "Event summary must be between 1 and 5000 characters"))]
    pub summary: String,
    pub source: String, // EventSource as string
    pub event_data: Option<JsonValue>,
}

impl NewChronicleEvent {
    /// Create a new event with EventSource enum
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
        }
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
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub order_by: Option<EventOrderBy>,
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
            limit: Some(50),
            offset: Some(0),
            order_by: Some(EventOrderBy::CreatedAtDesc),
        }
    }
}

impl From<CreateEventRequest> for NewChronicleEvent {
    fn from(request: CreateEventRequest) -> Self {
        Self {
            chronicle_id: Uuid::nil(), // Will be set by the service
            user_id: Uuid::nil(),      // Will be set by the service
            event_type: request.event_type,
            summary: request.summary,
            source: request.source.to_string(),
            event_data: request.event_data,
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