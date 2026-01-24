use crate::db::DbTimestamp;
use crate::models::OptionalStringArray;
use crate::schema::chronicle_events;
use chrono::Utc;
use diesel::{Identifiable, Insertable, Queryable, Selectable};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
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
/// Simplified to focus on summaries and searchable keywords
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = chronicle_events)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(feature = "sqlite-backend", not(feature = "postgres-backend")),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct ChronicleEvent {
    pub id: crate::db::DbId,
    pub chronicle_id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub event_type: String,
    pub summary: String, // Plaintext fallback (legacy)
    pub source: String,  // Will be converted to/from EventSource
    #[cfg(feature = "sqlite-backend")]
    pub event_data: Option<String>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    #[serde(skip_serializing)]
    pub summary_encrypted: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub summary_nonce: Option<Vec<u8>>,
    pub timestamp_iso8601: DbTimestamp,
    pub keywords: crate::db::DbStringArray, // For search optimization
    #[serde(skip_serializing)]
    pub keywords_encrypted: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub keywords_nonce: Option<Vec<u8>>,
    pub chat_session_id: Option<crate::db::DbId>, // Link to originating chat
    pub message_variant_id: Option<crate::db::DbId>, // Link to specific message variant
}

impl ChronicleEvent {
    /// Get the event source as an enum
    pub fn get_source(&self) -> Result<EventSource, String> {
        self.source.parse()
    }

    /// Get the decrypted summary using the provided DEK
    /// Falls back to legacy plaintext summary if encrypted version is not available
    pub fn get_decrypted_summary(
        &self,
        dek: &secrecy::SecretBox<Vec<u8>>,
    ) -> Result<String, crate::errors::AppError> {
        match (&self.summary_encrypted, &self.summary_nonce) {
            (Some(encrypted), Some(nonce)) => {
                // Decrypt the summary
                let decrypted_secret = crate::crypto::decrypt_gcm(encrypted, nonce, dek)
                    .map_err(|e| crate::errors::AppError::CryptoError(e.to_string()))?;
                let decrypted_bytes = decrypted_secret.expose_secret();
                String::from_utf8(decrypted_bytes.clone()).map_err(|e| {
                    crate::errors::AppError::SerializationError(format!(
                        "Failed to convert decrypted summary to UTF-8: {}",
                        e
                    ))
                })
            }
            _ => {
                // Fall back to legacy plaintext summary
                Ok(self.summary.clone())
            }
        }
    }

    /// Get the decrypted keywords using the provided DEK
    pub fn get_decrypted_keywords(
        &self,
        dek: &secrecy::SecretBox<Vec<u8>>,
    ) -> Result<Vec<String>, crate::errors::AppError> {
        match (&self.keywords_encrypted, &self.keywords_nonce) {
            (Some(encrypted), Some(nonce)) => {
                // Decrypt the keywords
                let decrypted_secret = crate::crypto::decrypt_gcm(encrypted, nonce, dek)
                    .map_err(|e| crate::errors::AppError::CryptoError(e.to_string()))?;
                let decrypted_bytes = decrypted_secret.expose_secret();
                let keywords_json = String::from_utf8(decrypted_bytes.clone()).map_err(|e| {
                    crate::errors::AppError::SerializationError(format!(
                        "Failed to convert decrypted keywords to UTF-8: {}",
                        e
                    ))
                })?;
                serde_json::from_str(&keywords_json).map_err(|e| {
                    crate::errors::AppError::SerializationError(format!(
                        "Failed to parse decrypted keywords JSON: {}",
                        e
                    ))
                })
            }
            _ => {
                // Fall back to plaintext keywords if available
                Ok(self
                    .keywords
                    .as_ref()
                    .map(|k| k.iter().filter_map(|opt| opt.clone()).collect())
                    .unwrap_or_default())
            }
        }
    }

    /// Check if this event has encrypted summary
    pub fn has_encrypted_summary(&self) -> bool {
        self.summary_encrypted.is_some() && self.summary_nonce.is_some()
    }

    /// Check if this event has encrypted keywords
    pub fn has_encrypted_keywords(&self) -> bool {
        self.keywords_encrypted.is_some() && self.keywords_nonce.is_some()
    }

    /// Get keywords for display (returns empty vec if none)
    pub fn get_keywords(&self) -> Vec<String> {
        self.keywords
            .as_ref()
            .map(|k| k.iter().filter_map(|opt| opt.clone()).collect())
            .unwrap_or_default()
    }
}

/// NewChronicleEvent for creating new events
/// Simplified structure focusing on summaries and keywords
#[derive(Debug, Clone, Insertable, Serialize, Deserialize, Validate)]
#[diesel(table_name = chronicle_events)]
#[cfg_attr(
    feature = "postgres-backend",
    diesel(check_for_backend(diesel::pg::Pg))
)]
#[cfg_attr(
    all(feature = "sqlite-backend", not(feature = "postgres-backend")),
    diesel(check_for_backend(diesel::sqlite::Sqlite))
)]
pub struct NewChronicleEvent {
    pub id: Option<crate::db::DbId>,
    pub chronicle_id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    #[validate(length(
        min = 1,
        max = 100,
        message = "Event type must be between 1 and 100 characters"
    ))]
    pub event_type: String,
    #[validate(length(
        min = 1,
        max = 5000,
        message = "Event summary must be between 1 and 5000 characters"
    ))]
    pub summary: String,
    pub source: String, // EventSource as string
    pub summary_encrypted: Option<Vec<u8>>,
    pub summary_nonce: Option<Vec<u8>>,
    pub timestamp_iso8601: DbTimestamp,
    pub keywords: crate::models::OptionalStringArray,
    pub keywords_encrypted: Option<Vec<u8>>,
    pub keywords_nonce: Option<Vec<u8>>,
    pub chat_session_id: Option<crate::db::DbId>,
    pub message_variant_id: Option<crate::db::DbId>,
}

impl Default for NewChronicleEvent {
    fn default() -> Self {
        Self {
            id: None,
            chronicle_id: crate::db::DbId::nil(),
            user_id: crate::db::DbId::nil(),
            event_type: "NARRATIVE.EVENT".to_string(),
            summary: String::new(),
            source: EventSource::AiExtracted.to_string(),
            summary_encrypted: None,
            summary_nonce: None,
            timestamp_iso8601: Utc::now().into(),
            keywords: OptionalStringArray(None),
            keywords_encrypted: None,
            keywords_nonce: None,
            chat_session_id: None,
            message_variant_id: None,
        }
    }
}

impl NewChronicleEvent {
    /// Create a new event with EventSource enum
    pub fn new(
        chronicle_id: crate::db::DbId,
        user_id: crate::db::DbId,
        event_type: String,
        summary: String,
        source: EventSource,
        keywords: Option<Vec<String>>,
        chat_session_id: Option<crate::db::DbId>,
        message_variant_id: Option<crate::db::DbId>,
    ) -> Self {
        Self {
            chronicle_id,
            user_id,
            event_type,
            summary,
            source: source.to_string(),
            keywords: OptionalStringArray(keywords.map(|k| k.into_iter().map(Some).collect())),
            chat_session_id,
            message_variant_id,
            ..Default::default()
        }
    }

    /// Create a simple event with just summary and keywords
    pub fn simple(
        chronicle_id: crate::db::DbId,
        user_id: crate::db::DbId,
        summary: String,
        keywords: Vec<String>,
        chat_session_id: Option<crate::db::DbId>,
        message_variant_id: Option<crate::db::DbId>,
    ) -> Self {
        Self::new(
            chronicle_id,
            user_id,
            "NARRATIVE.EVENT".to_string(), // Simple default type
            summary,
            EventSource::AiExtracted,
            Some(keywords),
            chat_session_id,
            message_variant_id,
        )
    }

    pub fn builder() -> NewChronicleEventBuilder {
        NewChronicleEventBuilder::default()
    }
}

#[derive(Default)]
pub struct NewChronicleEventBuilder {
    inner: NewChronicleEvent,
}

impl NewChronicleEventBuilder {
    pub fn chronicle_id(mut self, id: crate::db::DbId) -> Self {
        self.inner.chronicle_id = id;
        self
    }

    pub fn user_id(mut self, id: crate::db::DbId) -> Self {
        self.inner.user_id = id;
        self
    }

    pub fn event_type(mut self, event_type: impl Into<String>) -> Self {
        self.inner.event_type = event_type.into();
        self
    }

    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.inner.summary = summary.into();
        self
    }

    pub fn source(mut self, source: EventSource) -> Self {
        self.inner.source = source.to_string();
        self
    }

    pub fn keywords(mut self, keywords: Vec<String>) -> Self {
        self.inner.keywords = OptionalStringArray(Some(keywords.into_iter().map(Some).collect()));
        self
    }

    pub fn chat_session_id(mut self, id: Option<crate::db::DbId>) -> Self {
        self.inner.chat_session_id = id;
        self
    }

    pub fn message_variant_id(mut self, id: Option<crate::db::DbId>) -> Self {
        self.inner.message_variant_id = id;
        self
    }

    pub fn timestamp_iso8601(mut self, timestamp: crate::db::DbTimestamp) -> Self {
        self.inner.timestamp_iso8601 = timestamp;
        self
    }

    pub fn keywords_array(mut self, keywords: OptionalStringArray) -> Self {
        self.inner.keywords = keywords;
        self
    }

    pub fn build(self) -> NewChronicleEvent {
        self.inner
    }
}

/// UpdateChronicleEvent for updating existing events
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UpdateChronicleEvent {
    #[validate(length(
        min = 1,
        max = 100,
        message = "Event type must be between 1 and 100 characters"
    ))]
    pub event_type: Option<String>,
    #[validate(length(
        min = 1,
        max = 5000,
        message = "Event summary must be between 1 and 5000 characters"
    ))]
    pub summary: Option<String>,
    pub source: Option<EventSource>,
    pub keywords: Option<Vec<String>>,
}

/// Validate keywords count to prevent resource exhaustion
fn validate_keywords_count(keywords: &[String]) -> Result<(), validator::ValidationError> {
    const MAX_KEYWORDS: usize = 100;
    if keywords.len() > MAX_KEYWORDS {
        let mut err = validator::ValidationError::new("keywords_too_many");
        err.message = Some(
            format!(
                "Too many keywords: maximum {} allowed, got {}",
                MAX_KEYWORDS,
                keywords.len()
            )
            .into(),
        );
        return Err(err);
    }
    Ok(())
}

/// DTO for event creation from API
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateEventRequest {
    #[validate(length(
        min = 1,
        max = 100,
        message = "Event type must be between 1 and 100 characters"
    ))]
    pub event_type: String,
    #[validate(length(
        min = 1,
        max = 5000,
        message = "Event summary must be between 1 and 5000 characters"
    ))]
    pub summary: String,
    #[serde(default = "default_event_source")]
    pub source: EventSource,
    #[validate(custom(function = "validate_keywords_count"))]
    pub keywords: Option<Vec<String>>,
    pub timestamp_iso8601: Option<DbTimestamp>,
    pub chat_session_id: Option<crate::db::DbId>,
    pub message_variant_id: Option<crate::db::DbId>,
}

fn default_event_source() -> EventSource {
    EventSource::UserAdded
}

/// DTO for event update from API
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct UpdateEventRequest {
    #[validate(length(
        min = 1,
        max = 100,
        message = "Event type must be between 1 and 100 characters"
    ))]
    pub event_type: Option<String>,
    #[validate(length(
        min = 1,
        max = 5000,
        message = "Event summary must be between 1 and 5000 characters"
    ))]
    pub summary: Option<String>,
    pub source: Option<EventSource>,
    pub keywords: Option<Vec<String>>,
}

/// Filter options for querying events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    pub event_type: Option<String>,
    pub source: Option<EventSource>,
    pub keywords: Option<Vec<String>>, // Filter by keywords
    pub after_timestamp: Option<DbTimestamp>,
    pub before_timestamp: Option<DbTimestamp>,
    pub chat_session_id: Option<crate::db::DbId>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub order_by: Option<EventOrderBy>,
    pub active_variant_id: Option<crate::db::DbId>, // The variant we are currently viewing
    pub allowed_variant_ids: Option<Vec<crate::db::DbId>>, // Calculated list of valid ancestor variants
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
    #[serde(rename = "timestamp_asc")]
    TimestampAsc,
    #[serde(rename = "timestamp_desc")]
    TimestampDesc,
}

impl Default for EventFilter {
    fn default() -> Self {
        Self {
            event_type: None,
            source: None.into(),
            keywords: None,
            after_timestamp: None,
            before_timestamp: None,
            chat_session_id: None,
            limit: Some(50),
            offset: Some(0),
            order_by: Some(EventOrderBy::TimestampDesc),
            active_variant_id: None,
            allowed_variant_ids: None,
        }
    }
}

impl From<CreateEventRequest> for NewChronicleEvent {
    fn from(request: CreateEventRequest) -> Self {
        let timestamp = request
            .timestamp_iso8601
            .unwrap_or_else(|| Utc::now().into());

        NewChronicleEvent::builder()
            .event_type(request.event_type)
            .summary(request.summary)
            .source(request.source)
            .timestamp_iso8601(timestamp)
            .keywords_array(OptionalStringArray(
                request.keywords.map(|k| k.into_iter().map(Some).collect()),
            ))
            .chat_session_id(request.chat_session_id)
            .message_variant_id(request.message_variant_id)
            .build()
    }
}

impl From<UpdateEventRequest> for UpdateChronicleEvent {
    fn from(request: UpdateEventRequest) -> Self {
        Self {
            event_type: request.event_type,
            summary: request.summary,
            source: request.source,
            keywords: request.keywords,
        }
    }
}
